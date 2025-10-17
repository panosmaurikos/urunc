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

package unikernels

import (
	"fmt"
	"net"
	"runtime"
	"strings"

	"github.com/urunc-dev/urunc/pkg/unikontainers/types"
)

const LinuxUnikernel string = "linux"

type Linux struct {
	App        string
	Command    string
	Env        []string
	Net        LinuxNet
	RootFsType string
}

type LinuxNet struct {
	Address string
	Gateway string
	Mask    string
}

func IsIPInSubnet(ln LinuxNet) bool {
	ip := net.ParseIP(ln.Address)
	gw := net.ParseIP(ln.Gateway)
	mask := net.IPMask(net.ParseIP(ln.Mask).To4())
	subnet := gw.Mask(mask)

	return ip.Mask(mask).Equal(subnet)
}

func (l *Linux) CommandString() (string, error) {
	rdinit := ""
	bootParams := "panic=-1"

	// TODO: Check if this check causes any performance drop
	// or explore alternative implementations
	consoleStr := ""
	if runtime.GOARCH == "arm64" {
		consoleStr = "console=ttyAMA0"
	} else {
		consoleStr = "console=ttyS0"
	}
	bootParams += " " + consoleStr

	switch l.RootFsType {
	case "block":
		rootParams := "root=/dev/vda rw"
		bootParams += " " + rootParams
	case "initrd":
		rootParams := "root=/dev/ram0 rw"
		rdinit = "rd"
		bootParams += " " + rootParams
	case "9pfs":
		rootParams := "root=fs0 rw rootfstype=9p rootflags="
		rootParams += "trans=virtio,version=9p2000.L,msize=5000000,cache=mmap,posixacl"
		bootParams += " " + rootParams
	case "virtiofs":
		rootParams := "root=fs0 rw rootfstype=virtiofs"
		bootParams += " " + rootParams
	}
	if l.Net.Address != "" {
		netParams := fmt.Sprintf("ip=%s::%s:%s:urunc:eth0:off",
			l.Net.Address,
			l.Net.Gateway,
			l.Net.Mask)
		bootParams += " " + netParams
	}
	if !IsIPInSubnet(l.Net) {
		bootParams += " URUNIT_DEFROUTE=1"
	}
	for _, eVar := range l.Env {
		bootParams += " " + eVar
	}
	if l.App != "" {
		initParams := rdinit + "init=" + l.App + " -- " + l.Command
		bootParams += " " + initParams
	}

	return bootParams, nil
}

func (l *Linux) SupportsBlock() bool {
	return true
}

func (l *Linux) SupportsFS(fsType string) bool {
	switch fsType {
	case "ext2":
		return true
	case "ext3":
		return true
	case "ext4":
		return true
	case "9pfs":
		return true
	case "virtiofs":
		return true
	default:
		return false
	}
}

func (l *Linux) MonitorNetCli(_ string, _ string, _ string) string {
	return ""
}

func (l *Linux) MonitorBlockCli(monitor string) string {
	switch monitor {
	case "qemu":
		bcli := " -device virtio-blk-pci,id=blk0,drive=hd0"
		bcli += " -drive format=raw,if=none,id=hd0,file="
		return bcli
	default:
		return ""
	}
}

func (l *Linux) MonitorCli(monitor string) string {
	switch monitor {
	case "qemu":
		return " -no-reboot -serial stdio -nodefaults"
	default:
		return ""
	}
}

func (l *Linux) Init(data types.UnikernelParams) error {
	// Handling of args with spaces:
	// In Linux boot parameters we can not pass multi-word cli arguments
	// in init, because they are treated as separate cli arguments.
	// TO overcome this we make a convention with urunit:
	// 1. We wrap every multi-word cli argument in "'"
	// 2. When urunit reads such arguments will combine them and
	//    pass them to the app as one argument.
	for i, arg := range data.CmdLine {
		arg = strings.TrimSpace(arg)
		spaces := strings.Index(arg, " ")
		if spaces > 0 {
			data.CmdLine[i] = "'" + arg + "'"
		}
	}
	// we use the first argument in the cli args as the app name and the
	// rest as its arguments.
	switch len(data.CmdLine) {
	case 0:
		return fmt.Errorf("No init was specified")
	case 1:
		l.App = data.CmdLine[0]
		l.Command = ""
	default:
		l.App = data.CmdLine[0]
		l.Command = strings.Join(data.CmdLine[1:], " ")
	}

	l.Net.Address = data.Net.IP
	l.Net.Gateway = data.Net.Gateway
	l.Net.Mask = data.Net.Mask

	l.RootFsType = data.RootfsType
	l.Env = data.EnvVars
	return nil
}

func newLinux() *Linux {
	linuxStruct := new(Linux)
	return linuxStruct
}
