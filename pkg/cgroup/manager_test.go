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

package cgroup

import (
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func TestNewManager(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid config - sandbox only",
			cfg: Config{
				CgroupPath:        "/test/cgroup",
				ContainerID:       "test123",
				SandboxCgroupOnly: true,
				OverheadPath:      "/urunc_overhead",
			},
			wantErr: false,
		},
		{
			name: "valid config - split policy",
			cfg: Config{
				CgroupPath:        "/test/cgroup",
				ContainerID:       "test456",
				SandboxCgroupOnly: false,
				OverheadPath:      "/urunc_overhead",
			},
			wantErr: false,
		},
		{
			name: "empty cgroup path",
			cfg: Config{
				CgroupPath:  "",
				ContainerID: "test789",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr, err := NewManager(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewManager() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && mgr == nil {
				t.Error("NewManager() returned nil manager")
			}
		})
	}
}

func TestSharesToWeight(t *testing.T) {
	tests := []struct {
		name   string
		shares uint64
		want   uint64
	}{
		{
			name:   "default shares (1024)",
			shares: 1024,
			want:   100,
		},
		{
			name:   "minimum shares (2)",
			shares: 2,
			want:   1, // (2 * 100) / 1024 = 0.195 -> clamped to 1
		},
		{
			name:   "maximum shares (262144)",
			shares: 262144,
			want:   10000, // (262144 * 100) / 1024 = 25600 -> clamped to 10000
		},
		{
			name:   "zero shares",
			shares: 0,
			want:   100, // default
		},
		{
			name:   "half default (512)",
			shares: 512,
			want:   50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sharesToWeight(tt.shares)
			if got != tt.want {
				t.Errorf("sharesToWeight(%d) = %d, want %d", tt.shares, got, tt.want)
			}
		})
	}
}

func TestNormalizeCgroupPath(t *testing.T) {
	tests := []struct {
		name        string
		cgroupPath  string
		containerID string
		want        string
	}{
		{
			name:        "absolute path",
			cgroupPath:  "/kubepods/pod123/container456",
			containerID: "container456",
			want:        "/kubepods/pod123/container456",
		},
		{
			name:        "relative path",
			cgroupPath:  "kubepods/pod123/container456",
			containerID: "container456",
			want:        "kubepods/pod123/container456",
		},
		{
			name:        "empty path uses container ID",
			cgroupPath:  "",
			containerID: "container789",
			want:        "container789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeCgroupPath(tt.cgroupPath, tt.containerID)
			if got != tt.want {
				t.Errorf("normalizeCgroupPath(%q, %q) = %q, want %q",
					tt.cgroupPath, tt.containerID, got, tt.want)
			}
		})
	}
}

func TestIsVCPUThread(t *testing.T) {
	tests := []struct {
		name       string
		threadName string
		want       bool
	}{
		{
			name:       "QEMU vCPU thread with KVM",
			threadName: "CPU 0/KVM",
			want:       true,
		},
		{
			name:       "QEMU vCPU thread simple",
			threadName: "CPU 1/KVM",
			want:       true,
		},
		{
			name:       "generic vcpu thread",
			threadName: "vcpu0",
			want:       true,
		},
		{
			name:       "Firecracker vCPU thread",
			threadName: "fc_vcpu0",
			want:       true,
		},
		{
			name:       "Firecracker vCPU thread 2",
			threadName: "fc_vcpu1",
			want:       true,
		},
		{
			name:       "I/O thread",
			threadName: "IO 0",
			want:       false,
		},
		{
			name:       "main thread",
			threadName: "qemu-system-x86",
			want:       false,
		},
		{
			name:       "worker thread",
			threadName: "worker0",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isVCPUThread(tt.threadName)
			if got != tt.want {
				t.Errorf("isVCPUThread(%q) = %v, want %v", tt.threadName, got, tt.want)
			}
		})
	}
}

func TestSpecToCgroupResources(t *testing.T) {
	// Test CPU shares conversion
	shares := uint64(2048)
	quota := int64(50000)
	period := uint64(100000)

	spec := &specs.LinuxResources{
		CPU: &specs.LinuxCPU{
			Shares: &shares,
			Quota:  &quota,
			Period: &period,
			Cpus:   "0-1",
			Mems:   "0",
		},
	}

	res, err := specToCgroupResources(spec)
	if err != nil {
		t.Fatalf("specToCgroupResources() error = %v", err)
	}

	if res.CPU == nil {
		t.Fatal("CPU resources not set")
	}

	if res.CPU.Weight == nil {
		t.Fatal("CPU weight not set")
	}

	expectedWeight := sharesToWeight(shares)
	if *res.CPU.Weight != expectedWeight {
		t.Errorf("CPU weight = %d, want %d", *res.CPU.Weight, expectedWeight)
	}

	if res.CPU.Cpus != "0-1" {
		t.Errorf("CPU cpus = %q, want %q", res.CPU.Cpus, "0-1")
	}

	if res.CPU.Mems != "0" {
		t.Errorf("CPU mems = %q, want %q", res.CPU.Mems, "0")
	}
}

func TestSpecToCgroupResources_Memory(t *testing.T) {
	limit := int64(536870912) // 512MB
	swap := int64(1073741824)  // 1GB
	reservation := int64(268435456) // 256MB

	spec := &specs.LinuxResources{
		Memory: &specs.LinuxMemory{
			Limit:       &limit,
			Swap:        &swap,
			Reservation: &reservation,
		},
	}

	res, err := specToCgroupResources(spec)
	if err != nil {
		t.Fatalf("specToCgroupResources() error = %v", err)
	}

	if res.Memory == nil {
		t.Fatal("Memory resources not set")
	}

	if res.Memory.Max == nil || *res.Memory.Max != limit {
		t.Errorf("Memory max = %v, want %d", res.Memory.Max, limit)
	}

	if res.Memory.Swap == nil || *res.Memory.Swap != swap {
		t.Errorf("Memory swap = %v, want %d", res.Memory.Swap, swap)
	}

	if res.Memory.Low == nil || *res.Memory.Low != reservation {
		t.Errorf("Memory low = %v, want %d", res.Memory.Low, reservation)
	}
}

func TestSpecToCgroupResources_Pids(t *testing.T) {
	pidsLimit := int64(1024)

	spec := &specs.LinuxResources{
		Pids: &specs.LinuxPids{
			Limit: pidsLimit,
		},
	}

	res, err := specToCgroupResources(spec)
	if err != nil {
		t.Fatalf("specToCgroupResources() error = %v", err)
	}

	if res.Pids == nil {
		t.Fatal("Pids resources not set")
	}

	if res.Pids.Max != pidsLimit {
		t.Errorf("Pids max = %d, want %d", res.Pids.Max, pidsLimit)
	}
}

func TestSpecToCgroupResources_NilResources(t *testing.T) {
	res, err := specToCgroupResources(nil)
	if err != nil {
		t.Fatalf("specToCgroupResources(nil) error = %v", err)
	}

	if res == nil {
		t.Fatal("Expected non-nil result for nil input")
	}

	// All fields should be nil/empty
	if res.CPU != nil || res.Memory != nil || res.Pids != nil || res.IO != nil {
		t.Error("Expected all resource fields to be nil for nil input")
	}
}
