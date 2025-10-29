// Copyright (c) 2023-2025, Nubificus LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package unikontainers

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// setupConsoleForTerminal creates a PTY inside the container and sets up /dev/console.
// The function opens /dev/ptmx to create a new pseudo-terminal, unlocks the PTY slave,
// and retrieves its path. It then sends the PTY master file descriptor to containerd
// via the console socket. Finally, it bind mounts the PTY slave to /dev/console,
// duplicates it to stdin, stdout, and stderr, and sets it as the controlling terminal
// of the process to enable proper job control and interactive terminal functionality.
func setupConsoleForTerminal() error {
	// Get console socket path from environment
	consoleSocket := os.Getenv("_URUNC_CONSOLE_SOCKET")
	if consoleSocket == "" {
		return fmt.Errorf("terminal requested but console socket not provided")
	}

	// Open /dev/ptmx to create a new PTY
	ptmx, err := os.OpenFile("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("failed to open /dev/ptmx: %w", err)
	}

	// Unlock the PTY slave
	if err := unix.IoctlSetInt(int(ptmx.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		return fmt.Errorf("failed to unlock PTY: %w", err)
	}

	// Get PTY slave number
	ptyNum, err := unix.IoctlGetInt(int(ptmx.Fd()), unix.TIOCGPTN)
	if err != nil {
		return fmt.Errorf("failed to get PTY number: %w", err)
	}

	// Construct PTY slave path
	ptsPath := fmt.Sprintf("/dev/pts/%d", ptyNum)

	// Send PTY master FD to containerd via console socket
	conn, err := net.Dial("unix", consoleSocket)
	if err != nil {
		return fmt.Errorf("failed to dial console socket: %w", err)
	}
	defer conn.Close()

	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("failed to cast to UnixConn")
	}

	// Send PTY master file descriptor over socket
	oob := unix.UnixRights(int(ptmx.Fd()))
	_, _, err = uc.WriteMsgUnix([]byte(ptsPath), oob, nil)
	if err != nil {
		return fmt.Errorf("failed to send PTY master FD: %w", err)
	}

	// Open the PTY slave
	pts, err := os.OpenFile(ptsPath, unix.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return fmt.Errorf("failed to open PTY slave: %w", err)
	}
	//defer pts.Close()
	// Bind mount PTY slave to /dev/console
	err = unix.Mount(ptsPath, "/dev/console", "bind", unix.MS_BIND, "")
	if err != nil {
		return fmt.Errorf("failed to bind mount PTY slave to /dev/console: %w", err)
	}

	// Dup PTY slave to stdin, stdout, stderr
	for fd := 0; fd <= 2; fd++ {
		if err := unix.Dup3(int(pts.Fd()), fd, 0); err != nil {
			return fmt.Errorf("failed to dup PTY slave to fd %d: %w", fd, err)
		}
	}

	return nil
}
