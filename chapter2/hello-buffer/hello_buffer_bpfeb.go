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

// loadHello_buffer returns the embedded CollectionSpec for hello_buffer.
func loadHello_buffer() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_Hello_bufferBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load hello_buffer: %w", err)
	}

	return spec, err
}

// loadHello_bufferObjects loads hello_buffer and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*hello_bufferObjects
//	*hello_bufferPrograms
//	*hello_bufferMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadHello_bufferObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadHello_buffer()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// hello_bufferSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type hello_bufferSpecs struct {
	hello_bufferProgramSpecs
	hello_bufferMapSpecs
	hello_bufferVariableSpecs
}

// hello_bufferProgramSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type hello_bufferProgramSpecs struct {
	Hello *ebpf.ProgramSpec `ebpf:"hello"`
}

// hello_bufferMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type hello_bufferMapSpecs struct {
	Output *ebpf.MapSpec `ebpf:"output"`
}

// hello_bufferVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type hello_bufferVariableSpecs struct {
}

// hello_bufferObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadHello_bufferObjects or ebpf.CollectionSpec.LoadAndAssign.
type hello_bufferObjects struct {
	hello_bufferPrograms
	hello_bufferMaps
	hello_bufferVariables
}

func (o *hello_bufferObjects) Close() error {
	return _Hello_bufferClose(
		&o.hello_bufferPrograms,
		&o.hello_bufferMaps,
	)
}

// hello_bufferMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadHello_bufferObjects or ebpf.CollectionSpec.LoadAndAssign.
type hello_bufferMaps struct {
	Output *ebpf.Map `ebpf:"output"`
}

func (m *hello_bufferMaps) Close() error {
	return _Hello_bufferClose(
		m.Output,
	)
}

// hello_bufferVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to loadHello_bufferObjects or ebpf.CollectionSpec.LoadAndAssign.
type hello_bufferVariables struct {
}

// hello_bufferPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadHello_bufferObjects or ebpf.CollectionSpec.LoadAndAssign.
type hello_bufferPrograms struct {
	Hello *ebpf.Program `ebpf:"hello"`
}

func (p *hello_bufferPrograms) Close() error {
	return _Hello_bufferClose(
		p.Hello,
	)
}

func _Hello_bufferClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed hello_buffer_bpfeb.o
var _Hello_bufferBytes []byte
