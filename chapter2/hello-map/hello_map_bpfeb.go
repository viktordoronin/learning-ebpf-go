// Code generated by bpf2go; DO NOT EDIT.
//go:build mips || mips64 || ppc64 || s390x

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadHello_map returns the embedded CollectionSpec for hello_map.
func loadHello_map() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_Hello_mapBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load hello_map: %w", err)
	}

	return spec, err
}

// loadHello_mapObjects loads hello_map and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*hello_mapObjects
//	*hello_mapPrograms
//	*hello_mapMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadHello_mapObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadHello_map()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// hello_mapSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type hello_mapSpecs struct {
	hello_mapProgramSpecs
	hello_mapMapSpecs
	hello_mapVariableSpecs
}

// hello_mapProgramSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type hello_mapProgramSpecs struct {
	Hello *ebpf.ProgramSpec `ebpf:"hello"`
}

// hello_mapMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type hello_mapMapSpecs struct {
	CounterTable *ebpf.MapSpec `ebpf:"counter_table"`
}

// hello_mapVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type hello_mapVariableSpecs struct {
}

// hello_mapObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadHello_mapObjects or ebpf.CollectionSpec.LoadAndAssign.
type hello_mapObjects struct {
	hello_mapPrograms
	hello_mapMaps
	hello_mapVariables
}

func (o *hello_mapObjects) Close() error {
	return _Hello_mapClose(
		&o.hello_mapPrograms,
		&o.hello_mapMaps,
	)
}

// hello_mapMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadHello_mapObjects or ebpf.CollectionSpec.LoadAndAssign.
type hello_mapMaps struct {
	CounterTable *ebpf.Map `ebpf:"counter_table"`
}

func (m *hello_mapMaps) Close() error {
	return _Hello_mapClose(
		m.CounterTable,
	)
}

// hello_mapVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to loadHello_mapObjects or ebpf.CollectionSpec.LoadAndAssign.
type hello_mapVariables struct {
}

// hello_mapPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadHello_mapObjects or ebpf.CollectionSpec.LoadAndAssign.
type hello_mapPrograms struct {
	Hello *ebpf.Program `ebpf:"hello"`
}

func (p *hello_mapPrograms) Close() error {
	return _Hello_mapClose(
		p.Hello,
	)
}

func _Hello_mapClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed hello_map_bpfeb.o
var _Hello_mapBytes []byte
