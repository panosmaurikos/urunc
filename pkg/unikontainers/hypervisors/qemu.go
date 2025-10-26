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

package hypervisors

import (
	"fmt"
	"runtime"
	"strings"
	"syscall"

	"github.com/urunc-dev/urunc/pkg/unikontainers/types"
)

const (
	QemuVmm    VmmType = "qemu"
	QemuBinary string  = "qemu-system-"
)

type Qemu struct {
	binaryPath string
	binary     string
}

func (q *Qemu) Stop(_ string) error {
	return nil
}

func (q *Qemu) Ok() error {
	return nil
}

// UsesKVM returns a bool value depending on if the monitor uses KVM
func (q *Qemu) UsesKVM() bool {
	return true
}

// SupportsSharedfs returns a bool value depending on the monitor support for shared-fs
func (q *Qemu) SupportsSharedfs(_ string) bool {
	return true
}

func (q *Qemu) Path() string {
	return q.binaryPath
}

func (q *Qemu) Execve(args types.ExecArgs, ukernel types.Unikernel) error {
	qemuString := string(QemuVmm)
	qemuMem := BytesToStringMB(args.MemSizeB)
	cmdString := q.binaryPath + " -m " + qemuMem + "M"
	cmdString += " -L /usr/share/qemu"   // Set the path for qemu bios/data
	cmdString += " -cpu host"            // Choose CPU
	cmdString += " -enable-kvm"          // Enable KVM to use CPU virt extensions
	cmdString += " -nographic -vga none" // Disable graphic output

	if args.VCPUs > 0 {
		cmdString += fmt.Sprintf(" -smp %d", args.VCPUs)
	}

	if args.Seccomp {
		// Enable Seccomp in QEMU
		cmdString += " --sandbox on"
		// Allow or Deny Obsolete system calls
		cmdString += ",obsolete=deny"
		// Allow or Deny set*uid|gid system calls
		cmdString += ",elevateprivileges=deny"
		// Allow or Deny *fork and execve
		cmdString += ",spawn=deny"
		// Allow or Deny process affinity and schedular priority
		cmdString += ",resourcecontrol=deny"
	}

	// TODO: Check if this check causes any performance drop
	// or explore alternative implementations
	if runtime.GOARCH == "arm64" {
		machineType := " -M virt"
		cmdString += machineType
	}

	cmdString += " -kernel " + args.UnikernelPath
	if args.Net.TapDev != "" {
		netcli := ukernel.MonitorNetCli(qemuString, args.Net.TapDev, args.Net.MAC)
		if netcli == "" {
			netcli += " -net nic,model=virtio,macaddr="
			netcli += args.Net.MAC
			netcli += " -net tap,script=no,downscript=no,ifname="
			netcli += args.Net.TapDev
		}
		cmdString += netcli
	} else {
		cmdString += " -nic none"
	}
	if args.Block.Image != "" {
		blockCli := ukernel.MonitorBlockCli(qemuString)
		if blockCli == "" {
			blockCli += " -device virtio-blk-pci,id=blk0,drive=hd0,scsi=off"
			blockCli += " -drive format=raw,if=none,id=hd0,file="
		}
		blockCli += args.Block.Image
		cmdString += blockCli
	}
	if args.InitrdPath != "" {
		cmdString += " -initrd " + args.InitrdPath
	}
	switch args.Sharedfs.Type {
	case "9pfs":
		cmdString += " -fsdev local,id=rootfs9p,security_model=none,path=" + args.Sharedfs.Path
		cmdString += " -device virtio-9p-pci,fsdev=rootfs9p,mount_tag=fs0"
	case "virtiofs":
		cmdString += " -object memory-backend-file,id=mem,size=" + qemuMem + "M,mem-path=/tmp,share=on"
		cmdString += " -numa node,memdev=mem"
		cmdString += " -chardev socket,id=char0,path=/tmp/vhostqemu"
		cmdString += " -device vhost-user-fs-pci,queue-size=1024,chardev=char0,tag=fs0"
	default:
		// Nothing to add
	}
	extraMonArgs := ukernel.MonitorCli(qemuString)
	if extraMonArgs.ExtraInitrd != "" {
		cmdString += " -initrd " + extraMonArgs.ExtraInitrd
	}
	cmdString += extraMonArgs.OtherArgs
	exArgs := strings.Split(cmdString, " ")
	exArgs = append(exArgs, "-append", args.Command)
	vmmLog.WithField("qemu command", exArgs).Debug("Ready to execve qemu")
	return syscall.Exec(q.Path(), exArgs, args.Environment) //nolint: gosec
}
