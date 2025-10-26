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

package types

type Unikernel interface {
	Init(UnikernelParams) error
	CommandString() (string, error)
	SupportsBlock() bool
	SupportsFS(string) bool
	MonitorNetCli(string, string, string) string
	MonitorBlockCli(string) string
	MonitorCli(string) MonitorCliArgs
}

type VMM interface {
	Execve(args ExecArgs, ukernel Unikernel) error
	Stop(t string) error
	Path() string
	UsesKVM() bool
	SupportsSharedfs(string) bool
	Ok() error
}

type NetDevParams struct {
	IP      string // The veth device IP
	Mask    string // The veth device mask
	Gateway string // The veth device gateway
	MAC     string // The MAC address of the guest network device
	TapDev  string // The tap device name
}

type BlockDevParams struct {
	Image      string
	MountPoint string
	FsType     string
	ID         uint
}

type SharedfsParams struct {
	Type string // The type of shared-fs 9p or virtiofs
	Path string // The path in the host to share with guest
}

type RootfsParams struct {
	Type        string // The type of rootfs (block, initrd, 9pfs, virtiofs)
	Path        string // The path in the host where rootfs resides
	MountedPath string // The mountpoint in the host where the rootfs is mounted
	MonRootfs   string // The rootfs for the monitor process
}

// UnikernelParams holds the data required to build the unikernels commandline
type UnikernelParams struct {
	CmdLine    []string // The cmdline provided by the image
	EnvVars    []string // The environment variables provided by the image
	Version    string   // The version of the unikernel
	InitrdPath string   // The path to the initrd of the unikernel
	Net        NetDevParams
	Block      BlockDevParams
	Rootfs     RootfsParams // Information about rootfs
}

// ExecArgs holds the data required by Execve to start the VMM
// FIXME: add extra fields if required by additional VMM's
type ExecArgs struct {
	ContainerID   string   // The container ID
	Environment   []string // The environment variables of the monitor
	Command       string   // The unikernel's command line
	Seccomp       bool     // Enable or disable seccomp filters for the VMM
	MemSizeB      uint64   // The size of the memory provided to the VM in bytes
	VCPUs         uint     // The number of vCPUs to allocate
	UnikernelPath string   // The path of the unikernel inside rootfs
	InitrdPath    string   // The path to the initrd of the unikernel
	Net           NetDevParams
	Block         BlockDevParams
	Sharedfs      SharedfsParams
}

type MonitorCliArgs struct {
	ExtraInitrd string
	OtherArgs   string
}

// HypervisorConfig struct is used to hold hypervisor specific configuration
// that is parsed from the urunc config file or state.json annotations
type HypervisorConfig struct {
	DefaultMemoryMB uint   `toml:"default_memory_mb"`
	DefaultVCPUs    uint   `toml:"default_vcpus"`
	BinaryPath      string `toml:"binary_path,omitempty"` // Optional path to the hypervisor binary
}
