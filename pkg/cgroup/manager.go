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
	"context"
	"fmt"
	"strings"

	cgroupsv2 "github.com/containerd/cgroups/v3/cgroup2"
	"github.com/containerd/cgroups/v3/cgroup2/stats"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

var cgroupLog = logrus.WithField("subsystem", "cgroup")

// Manager handles cgroup lifecycle for urunc containers.
// Following Kata Containers' sandbox_cgroup_only approach:
// all processes (VMM, vCPU, I/O) run under the container's cgroup.
type Manager struct {
	cgroupMgr   *cgroupsv2.Manager
	cgroupPath  string
	containerID string
}

// Config holds configuration for cgroup creation
type Config struct {
	CgroupPath  string
	ContainerID string
	Resources   *specs.LinuxResources
	UseSystemd  bool
}

// NewManager creates a new cgroup manager
func NewManager(cfg Config) (*Manager, error) {
	if cfg.CgroupPath == "" {
		return nil, fmt.Errorf("cgroup path cannot be empty")
	}

	cgroupPath := normalizeCgroupPath(cfg.CgroupPath, cfg.ContainerID)

	m := &Manager{
		cgroupPath:  cgroupPath,
		containerID: cfg.ContainerID,
	}

	cgroupLog.WithFields(logrus.Fields{
		"cgroup_path":  cgroupPath,
		"container_id": cfg.ContainerID,
	}).Debug("Creating cgroup manager")

	return m, nil
}

// Create creates the cgroup and adds the process to it
func (m *Manager) Create(ctx context.Context, resources *specs.LinuxResources, pid int, useSystemd bool) error {
	cgroupResources, err := specToCgroupResources(resources)
	if err != nil {
		return fmt.Errorf("failed to convert resources: %w", err)
	}

	// Auto-detect systemd path format or use explicit flag
	useSystemdDriver := useSystemd || isSystemdPath(m.cgroupPath)

	if useSystemdDriver && isSystemdPath(m.cgroupPath) {
		slice, group, err := parseSystemdPath(m.cgroupPath)
		if err != nil {
			return fmt.Errorf("failed to parse systemd cgroup path %s: %w", m.cgroupPath, err)
		}

		cgroupLog.WithFields(logrus.Fields{
			"slice": slice,
			"group": group,
			"pid":   pid,
		}).Debug("Creating systemd cgroup")

		m.cgroupMgr, err = cgroupsv2.NewSystemd(slice, group, pid, cgroupResources)
		if err != nil {
			return fmt.Errorf("failed to create systemd cgroup %s:%s: %w", slice, group, err)
		}
	} else {
		m.cgroupMgr, err = cgroupsv2.NewManager(
			"/sys/fs/cgroup",
			m.cgroupPath,
			cgroupResources,
		)
		if err != nil {
			return fmt.Errorf("failed to create cgroup at %s: %w", m.cgroupPath, err)
		}

		if err := m.cgroupMgr.AddProc(uint64(pid)); err != nil {
			_ = m.cgroupMgr.Delete()
			return fmt.Errorf("failed to add pid %d to cgroup: %w", pid, err)
		}
	}

	cgroupLog.WithFields(logrus.Fields{
		"path": m.cgroupPath,
		"pid":  pid,
	}).Info("Created cgroup and added process")

	return nil
}

// Update updates cgroup resource limits
func (m *Manager) Update(resources *specs.LinuxResources) error {
	if m.cgroupMgr == nil {
		return fmt.Errorf("cgroup not initialized")
	}

	cgroupResources, err := specToCgroupResources(resources)
	if err != nil {
		return err
	}

	return m.cgroupMgr.Update(cgroupResources)
}

// Delete removes the cgroup
func (m *Manager) Delete() error {
	if m.cgroupMgr == nil {
		return nil
	}

	if err := m.cgroupMgr.Delete(); err != nil {
		cgroupLog.WithError(err).Error("Failed to delete cgroup")
		return fmt.Errorf("cgroup delete: %w", err)
	}

	return nil
}

// GetStats returns cgroup statistics
func (m *Manager) GetStats() (*stats.Metrics, error) {
	if m.cgroupMgr == nil {
		return nil, fmt.Errorf("cgroup not initialized")
	}

	return m.cgroupMgr.Stat()
}

// normalizeCgroupPath handles OCI cgroup path formats
func normalizeCgroupPath(cgroupPath, containerID string) string {
	if cgroupPath == "" {
		return containerID
	}

	if strings.HasPrefix(cgroupPath, "/") {
		return cgroupPath
	}

	return cgroupPath
}

// isSystemdPath checks if a cgroup path is in systemd format (slice:prefix:name)
func isSystemdPath(path string) bool {
	return strings.Contains(path, ":")
}

// parseSystemdPath parses a systemd cgroup path format
// Input: "slice:prefix:name" (e.g., "system.slice:docker:containerID")
// Output: slice ("system.slice"), group ("docker-containerID.scope")
func parseSystemdPath(path string) (string, string, error) {
	parts := strings.Split(path, ":")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid systemd path format: %s", path)
	}

	slice := parts[0]
	group := strings.Join(parts[1:], "-")
	if !strings.HasSuffix(group, ".scope") {
		group = group + ".scope"
	}

	cgroupLog.WithFields(logrus.Fields{
		"input": path,
		"slice": slice,
		"group": group,
	}).Debug("Parsed systemd cgroup path")

	return slice, group, nil
}

// specToCgroupResources converts OCI resources to cgroup v2 resources
func specToCgroupResources(spec *specs.LinuxResources) (*cgroupsv2.Resources, error) {
	if spec == nil {
		return &cgroupsv2.Resources{}, nil
	}

	res := &cgroupsv2.Resources{}

	// CPU resources
	if spec.CPU != nil {
		res.CPU = &cgroupsv2.CPU{}

		if spec.CPU.Shares != nil {
			weight := sharesToWeight(*spec.CPU.Shares)
			res.CPU.Weight = &weight
		}

		if spec.CPU.Quota != nil && spec.CPU.Period != nil {
			res.CPU.Max = cgroupsv2.NewCPUMax(spec.CPU.Quota, spec.CPU.Period)
		}

		if spec.CPU.Cpus != "" {
			res.CPU.Cpus = spec.CPU.Cpus
		}

		if spec.CPU.Mems != "" {
			res.CPU.Mems = spec.CPU.Mems
		}
	}

	// Memory resources
	if spec.Memory != nil {
		res.Memory = &cgroupsv2.Memory{}

		if spec.Memory.Limit != nil {
			res.Memory.Max = spec.Memory.Limit
		}

		if spec.Memory.Swap != nil {
			res.Memory.Swap = spec.Memory.Swap
		}

		if spec.Memory.Reservation != nil {
			res.Memory.Low = spec.Memory.Reservation
		}
	}

	// I/O resources
	if spec.BlockIO != nil {
		res.IO = &cgroupsv2.IO{}

		if spec.BlockIO.Weight != nil {
			res.IO.BFQ.Weight = uint16(*spec.BlockIO.Weight)
		}
	}

	// PID resources
	if spec.Pids != nil {
		res.Pids = &cgroupsv2.Pids{}

		if spec.Pids.Limit > 0 {
			res.Pids.Max = spec.Pids.Limit
		}
	}

	return res, nil
}

// sharesToWeight converts CPU shares (OCI) to CPU weight (cgroup v2)
// OCI shares range: 2-262144, default 1024
// cgroup v2 weight range: 1-10000, default 100
func sharesToWeight(shares uint64) uint64 {
	if shares == 0 {
		return 100
	}

	weight := (shares * 100) / 1024

	if weight < 1 {
		weight = 1
	}
	if weight > 10000 {
		weight = 10000
	}

	return weight
}
