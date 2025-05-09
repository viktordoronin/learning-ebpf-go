//go:generate go run github.com/cilium/ebpf/cmd/bpf2go hello_config hello-buffer-config.bpf.c

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

type bpfOutput struct{
	Pid int32
	Uid int32
	Command [16]byte
	Message [12]byte
}

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil { 
		log.Fatal("Removing memlock:", err)
	}
	// Load the compiled eBPF ELF and load it into the kernel.
	var objs hello_configObjects
	if err := loadHello_configObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. 
	kp, err := link.Kprobe("sys_execve", objs.Hello, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	//the "two additional lines" from the book
	objs.Config.Update(uint32(0),"Hey root!",ebpf.UpdateAny)
	objs.Config.Update(uint32(1000),"Hi user 1000",ebpf.UpdateAny)
	
	perfrd, err:=perf.NewReader(objs.Output,4096)
	if err!=nil {
		log.Fatal(err)
	}
	var output bpfOutput

	for{
		record, err := perfrd.Read()
		if err != nil {
			panic(err)
		}
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &output); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}
		fmt.Printf("%d %d %s %s\n", output.Uid, output.Pid, output.Command, output.Message)
	}
}
