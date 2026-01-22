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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	cgroupsv2 "github.com/containerd/cgroups/v3/cgroup2"
	"github.com/containerd/cgroups/v3/cgroup2/stats"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

var cgroupLog = logrus.WithField("subsystem", "cgroup")

// Manager handles cgroup lifecycle for urunc containers
type Manager struct {
	sandboxCgroup  *cgroupsv2.Manager
	overheadCgroup *cgroupsv2.Manager
	cgroupPath     string
	overheadPath   string
	splitPolicy    bool
	containerID    string
}

// Config holds configuration for cgroup creation
type Config struct {
	CgroupPath        string
	ContainerID       string
	Resources         *specs.LinuxResources
	SandboxCgroupOnly bool
	OverheadPath      string
	UseSystemd        bool // Whether to use systemd cgroup driver
}

// NewManager creates a new cgroup manager
func NewManager(cfg Config) (*Manager, error) {
	if cfg.CgroupPath == "" {
		return nil, fmt.Errorf("cgroup path cannot be empty")
	}

	cgroupPath := normalizeCgroupPath(cfg.CgroupPath, cfg.ContainerID)

	m := &Manager{
		cgroupPath:   cgroupPath,
		overheadPath: cfg.OverheadPath,
		splitPolicy:  !cfg.SandboxCgroupOnly,
		containerID:  cfg.ContainerID,
	}

	cgroupLog.WithFields(logrus.Fields{
		"cgroup_path":  cgroupPath,
		"split_policy": m.splitPolicy,
		"container_id": cfg.ContainerID,
	}).Debug("Creating cgroup manager")

	return m, nil
}

// Create creates the necessary cgroups
func (m *Manager) Create(ctx context.Context, resources *specs.LinuxResources, pid int, useSystemd bool) error {
	// Convert OCI resources to cgroup v2 resources
	cgroupResources, err := specToCgroupResources(resources)
	if err != nil {
		return fmt.Errorf("failed to convert resources: %w", err)
	}

	var sandboxMgr *cgroupsv2.Manager

	// Auto-detect systemd path format or use explicit flag
	useSystemdDriver := useSystemd || isSystemdPath(m.cgroupPath)

	// Create sandbox cgroup using appropriate method
	if useSystemdDriver && isSystemdPath(m.cgroupPath) {
		// Parse systemd path format: slice:prefix:name
		slice, group, err := parseSystemdPath(m.cgroupPath)
		if err != nil {
			return fmt.Errorf("failed to parse systemd cgroup path %s: %w", m.cgroupPath, err)
		}

		cgroupLog.WithFields(logrus.Fields{
			"slice": slice,
			"group": group,
			"pid":   pid,
		}).Debug("Creating systemd cgroup")

		sandboxMgr, err = cgroupsv2.NewSystemd(slice, group, pid, cgroupResources)
		if err != nil {
			return fmt.Errorf("failed to create systemd sandbox cgroup %s:%s: %w", slice, group, err)
		}
	} else {
		// Use filesystem-based cgroup manager
		sandboxMgr, err = cgroupsv2.NewManager(
			"/sys/fs/cgroup",
			m.cgroupPath,
			cgroupResources,
		)
		if err != nil {
			return fmt.Errorf("failed to create sandbox cgroup at %s: %w", m.cgroupPath, err)
		}

		// Add process to sandbox cgroup (NewSystemd already does this)
		if err := sandboxMgr.AddProc(uint64(pid)); err != nil {
			_ = sandboxMgr.Delete()
			return fmt.Errorf("failed to add pid %d to cgroup: %w", pid, err)
		}
	}

	m.sandboxCgroup = sandboxMgr

	cgroupLog.WithFields(logrus.Fields{
		"path": m.cgroupPath,
		"pid":  pid,
	}).Info("Created sandbox cgroup and added process")

	// If split policy, create overhead cgroup
	// Note: We always use filesystem-based cgroup for overhead, even with systemd,
	// because it's an internal urunc feature and doesn't need systemd integration
	if m.splitPolicy {
		overheadPath := filepath.Join(m.overheadPath, m.containerID)

		// Overhead gets minimal resources (no limits)
		overheadMgr, err := cgroupsv2.NewManager(
			"/sys/fs/cgroup",
			overheadPath,
			&cgroupsv2.Resources{},
		)
		if err != nil {
			_ = m.sandboxCgroup.Delete()
			return fmt.Errorf("failed to create overhead cgroup at %s: %w", overheadPath, err)
		}
		m.overheadCgroup = overheadMgr

		cgroupLog.WithField("path", overheadPath).Info("Created overhead cgroup")
	}

	return nil
}

// MoveVCPUThreads identifies vCPU threads and moves them FROM overhead TO sandbox cgroup.
// This assumes the VMM process is already in the overhead cgroup (moved before exec via MoveToOverhead).
// All threads initially inherit the overhead cgroup, and we selectively move only vCPU threads
// to the sandbox (workload) cgroup. I/O threads stay in overhead.
func (m *Manager) MoveVCPUThreads(vmmPid int) error {
	if !m.splitPolicy {
		// In sandbox_cgroup_only mode, all threads stay in sandbox cgroup
		return nil
	}

	cgroupLog.WithField("vmm_pid", vmmPid).Debug("Identifying and moving vCPU threads from overhead to sandbox cgroup")

	// Retry thread detection with exponential backoff
	// VMM may not spawn all vCPU threads immediately
	var vcpuThreads, ioThreads []int
	maxAttempts := 5
	var lastThreadCount int

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Read all threads of the VMM process
		threadIDs, err := getProcessThreads(vmmPid)
		if err != nil {
			cgroupLog.WithError(err).WithField("attempt", attempt+1).Warn("Failed to get threads")
			time.Sleep(50 * time.Millisecond * time.Duration(1<<uint(attempt)))
			continue
		}

		cgroupLog.WithFields(logrus.Fields{
			"vmm_pid":      vmmPid,
			"thread_count": len(threadIDs),
			"attempt":      attempt + 1,
		}).Debug("Found VMM threads")

		// Reset thread lists for this attempt
		vcpuThreads = []int{}
		ioThreads = []int{}

		// Identify vCPU threads vs I/O threads
		for _, tid := range threadIDs {
			threadName, err := getThreadName(vmmPid, tid)
			if err != nil {
				cgroupLog.WithError(err).WithField("tid", tid).Warn("Failed to get thread name")
				continue
			}

			if isVCPUThread(threadName) {
				vcpuThreads = append(vcpuThreads, tid)
				cgroupLog.WithFields(logrus.Fields{
					"tid":  tid,
					"name": threadName,
				}).Debug("Identified vCPU thread")
			} else {
				ioThreads = append(ioThreads, tid)
			}
		}

		// If we found vCPU threads, or thread count is stable, break
		if len(vcpuThreads) > 0 || (attempt > 0 && len(threadIDs) == lastThreadCount) {
			break
		}

		lastThreadCount = len(threadIDs)

		// Wait before retry with exponential backoff
		sleepDuration := 50 * time.Millisecond * time.Duration(1<<uint(attempt))
		cgroupLog.WithFields(logrus.Fields{
			"attempt":        attempt + 1,
			"sleep_duration": sleepDuration,
		}).Debug("No vCPU threads found yet, retrying")
		time.Sleep(sleepDuration)
	}

	cgroupLog.WithFields(logrus.Fields{
		"vcpu_threads": len(vcpuThreads),
		"io_threads":   len(ioThreads),
	}).Info("Classified VMM threads")

	// Pre-move strategy: ALL threads are currently in overhead cgroup
	// Move ONLY vCPU threads FROM overhead TO sandbox (workload)
	// I/O threads and main VMM process stay in overhead

	movedCount := 0
	for _, tid := range vcpuThreads {
		if err := m.sandboxCgroup.AddProc(uint64(tid)); err != nil {
			cgroupLog.WithError(err).WithField("tid", tid).Warn("Failed to move vCPU thread to sandbox cgroup")
		} else {
			movedCount++
		}
	}

	if len(vcpuThreads) == 0 {
		cgroupLog.Warn("No vCPU threads detected - all threads will stay in overhead cgroup. This may happen with single-vCPU setups or if thread naming patterns don't match.")
	}

	cgroupLog.WithFields(logrus.Fields{
		"vcpu_moved":      movedCount,
		"vcpu_total":      len(vcpuThreads),
		"io_in_overhead":  len(ioThreads),
		"vmm_in_overhead": true,
	}).Info("Successfully moved vCPU threads to sandbox cgroup")

	return nil
}

// MoveToOverhead moves a process to the overhead cgroup.
// This should be called by the reexec process BEFORE exec() so that
// the VMM and all its threads inherit the overhead cgroup.
func (m *Manager) MoveToOverhead(pid int) error {
	if !m.splitPolicy {
		return nil // No-op if not using split policy
	}

	if m.overheadCgroup == nil {
		return fmt.Errorf("overhead cgroup not initialized")
	}

	cgroupLog.WithFields(logrus.Fields{
		"pid": pid,
	}).Debug("Moving reexec process to overhead cgroup")

	// Add process to overhead cgroup
	if err := m.overheadCgroup.AddProc(uint64(pid)); err != nil {
		return fmt.Errorf("failed to add PID %d to overhead cgroup: %w", pid, err)
	}

	cgroupLog.WithFields(logrus.Fields{
		"pid": pid,
	}).Info("Successfully moved reexec process to overhead cgroup")

	return nil
}

// UsingSplitPolicy returns true if split cgroup policy is enabled
func (m *Manager) UsingSplitPolicy() bool {
	return m.splitPolicy
}

// Update updates cgroup resource limits
func (m *Manager) Update(resources *specs.LinuxResources) error {
	if m.sandboxCgroup == nil {
		return fmt.Errorf("sandbox cgroup not initialized")
	}

	cgroupResources, err := specToCgroupResources(resources)
	if err != nil {
		return err
	}

	return m.sandboxCgroup.Update(cgroupResources)
}

// Delete removes all cgroups
func (m *Manager) Delete() error {
	var errs []error

	if m.overheadCgroup != nil {
		if err := m.overheadCgroup.Delete(); err != nil {
			cgroupLog.WithError(err).Error("Failed to delete overhead cgroup")
			errs = append(errs, fmt.Errorf("overhead cgroup delete: %w", err))
		}
	}

	if m.sandboxCgroup != nil {
		if err := m.sandboxCgroup.Delete(); err != nil {
			cgroupLog.WithError(err).Error("Failed to delete sandbox cgroup")
			errs = append(errs, fmt.Errorf("sandbox cgroup delete: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("cgroup deletion errors: %v", errs)
	}

	return nil
}

// GetStats returns cgroup statistics
func (m *Manager) GetStats() (*stats.Metrics, error) {
	if m.sandboxCgroup == nil {
		return nil, fmt.Errorf("sandbox cgroup not initialized")
	}

	return m.sandboxCgroup.Stat()
}

// normalizeCgroupPath handles OCI cgroup path formats
func normalizeCgroupPath(cgroupPath, containerID string) string {
	if cgroupPath == "" {
		return containerID
	}

	// If it starts with /, it's an absolute path
	if strings.HasPrefix(cgroupPath, "/") {
		return cgroupPath
	}

	// Otherwise, it's a relative path
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

	// Construct group name from remaining parts
	// For "system.slice:docker:containerID" -> "docker-containerID.scope"
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

// getProcessThreads returns all thread IDs for a process
func getProcessThreads(pid int) ([]int, error) {
	taskDir := fmt.Sprintf("/proc/%d/task", pid)
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		return nil, err
	}

	threads := make([]int, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		tid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		threads = append(threads, tid)
	}

	return threads, nil
}

// getThreadName reads the thread name from /proc/<pid>/task/<tid>/comm
func getThreadName(pid, tid int) (string, error) {
	commPath := fmt.Sprintf("/proc/%d/task/%d/comm", pid, tid)
	data, err := os.ReadFile(commPath)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(data)), nil
}

// isVCPUThread determines if a thread is a vCPU thread based on its name
func isVCPUThread(name string) bool {
	// QEMU vCPU threads
	if strings.HasPrefix(name, "CPU ") || strings.Contains(name, "/KVM") {
		return true
	}
	// Firecracker vCPU threads
	if strings.HasPrefix(name, "fc_vcpu") {
		return true
	}
	// Generic vcpu naming
	if strings.HasPrefix(name, "vcpu") {
		return true
	}

	return false
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
		return 100 // default weight
	}

	// Convert shares to weight
	// Formula: weight = (shares * 100) / 1024
	weight := (shares * 100) / 1024

	if weight < 1 {
		weight = 1
	}
	if weight > 10000 {
		weight = 10000
	}

	return weight
}
