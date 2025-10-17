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
	"errors"
	"fmt"
	"os/exec"

	"github.com/sirupsen/logrus"
	"github.com/urunc-dev/urunc/pkg/unikontainers/types"
)

const DefaultMemory uint64 = 256 // The default memory for every hypervisor: 256 MB

type VmmType string

var ErrVMMNotInstalled = errors.New("vmm not found")
var vmmLog = logrus.WithField("subsystem", "hypervisors")

type VMMFactory struct {
	binary     string
	createFunc func(binary, binaryPath string) types.VMM
}

var vmmFactories = map[VmmType]VMMFactory{
	SptVmm: {
		binary:     SptBinary,
		createFunc: func(binary, binaryPath string) types.VMM { return &SPT{binary: binary, binaryPath: binaryPath} },
	},
	HvtVmm: {
		binary:     HvtBinary,
		createFunc: func(binary, binaryPath string) types.VMM { return &HVT{binary: binary, binaryPath: binaryPath} },
	},
	QemuVmm: {
		binary:     QemuBinary,
		createFunc: func(binary, binaryPath string) types.VMM { return &Qemu{binary: binary, binaryPath: binaryPath} },
	},
	FirecrackerVmm: {
		binary:     FirecrackerBinary,
		createFunc: func(binary, binaryPath string) types.VMM { return &Firecracker{binary: binary, binaryPath: binaryPath} },
	},
}

func NewVMM(vmmType VmmType, hypervisors map[string]types.HypervisorConfig) (vmm types.VMM, err error) {
	defer func() {
		if err != nil {
			vmmLog.Error(err.Error())
		}
	}()

	// Handle Hedge separately since it is not in vmmFactories
	if vmmType == HedgeVmm {
		hedge := Hedge{}
		if err := hedge.Ok(); err != nil {
			return nil, ErrVMMNotInstalled
		}
		return &hedge, nil
	}

	factory, exists := vmmFactories[vmmType]
	if !exists {
		return nil, fmt.Errorf("vmm \"%s\" is not supported", vmmType)
	}

	vmmPath, err := getVMMPath(vmmType, factory.binary, hypervisors)
	if err != nil {
		return nil, err
	}

	return factory.createFunc(factory.binary, vmmPath), nil
}

func getVMMPath(vmmType VmmType, binary string, hypervisors map[string]types.HypervisorConfig) (string, error) {
	if vmmPath := hypervisors[string(vmmType)].BinaryPath; vmmPath != "" {
		return vmmPath, nil
	}

	lookupBinary := binary
	if vmmType == QemuVmm {
		lookupBinary = binary + cpuArch()
	}

	vmmPath, err := exec.LookPath(lookupBinary)
	if err != nil {
		return "", ErrVMMNotInstalled
	}
	return vmmPath, nil
}
