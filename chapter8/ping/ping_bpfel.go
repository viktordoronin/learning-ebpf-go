// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadPing returns the embedded CollectionSpec for ping.
func loadPing() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_PingBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load ping: %w", err)
	}

	return spec, err
}

// loadPingObjects loads ping and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*pingObjects
//	*pingPrograms
//	*pingMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadPingObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadPing()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// pingSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type pingSpecs struct {
	pingProgramSpecs
	pingMapSpecs
	pingVariableSpecs
}

// pingProgramSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type pingProgramSpecs struct {
	Myxdp *ebpf.ProgramSpec `ebpf:"myxdp"`
}

// pingMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type pingMapSpecs struct {
}

// pingVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type pingVariableSpecs struct {
}

// pingObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadPingObjects or ebpf.CollectionSpec.LoadAndAssign.
type pingObjects struct {
	pingPrograms
	pingMaps
	pingVariables
}

func (o *pingObjects) Close() error {
	return _PingClose(
		&o.pingPrograms,
		&o.pingMaps,
	)
}

// pingMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadPingObjects or ebpf.CollectionSpec.LoadAndAssign.
type pingMaps struct {
}

func (m *pingMaps) Close() error {
	return _PingClose()
}

// pingVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to loadPingObjects or ebpf.CollectionSpec.LoadAndAssign.
type pingVariables struct {
}

// pingPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadPingObjects or ebpf.CollectionSpec.LoadAndAssign.
type pingPrograms struct {
	Myxdp *ebpf.Program `ebpf:"myxdp"`
}

func (p *pingPrograms) Close() error {
	return _PingClose(
		p.Myxdp,
	)
}

func _PingClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed ping_bpfel.o
var _PingBytes []byte
