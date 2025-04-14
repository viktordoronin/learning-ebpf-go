//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 hello hello.bpf.c
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	//	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

type bpfOutput struct{
	Pid int32
	Uid int32
	Command [16]byte
	Message [12]byte
	Path [16]byte
}

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil { 
		log.Fatal("Removing memlock:", err)
	}
	
	// Load the compiled eBPF ELF and load it into the kernel.
	var objs helloObjects
	if err := loadHelloObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}	
	defer objs.Close()

	//one thing libbpf does better is that it automatically attaches all the programs, here we have to do everything by hand
	kp, err := link.Kprobe("sys_execve", objs.KprobeSysExecve, nil)
	if err != nil {
		log.Fatalf("opening ksyscall: %s", err)
	}
	defer kp.Close()

	//do_execve isn't available on all systems, this is what I have on mine
	kd, err := link.Kprobe("do_execveat_common.isra.0", objs.KprobeDoExecve, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kd.Close()

	//normal tracepoint attachment has this handy method that raw tps don't
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TpSysEnterExecve, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer tp.Close()

	//this is how you do a BTF tracepoint: look up BPF_PROG_TYPE_TRACING for more info 
	tracing, err := link.AttachTracing(link.TracingOptions{Program:objs.TpBtfExec})
	if err != nil {
		log.Fatalf("opening tracing: %s", err)
	}
	defer tracing.Close()

	//this is a raw TP, which we do similarly to hello-tail from Ch.2
	rtp, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name:"sched_process_exec",Program:objs.RawTpExec})
	if err != nil {
		log.Fatalf("opening raw tracepoint: %s", err)
	}
	defer rtp.Close()

	//fentry isn't supported on my system because I use WSL with 5.15 kernel
	//nevertheless, here's how to do it: it's just Tracing
	// fentry, err := link.AttachTracing(link.TracingOptions{Program:objs.FentryExecve})
	// if err != nil {
	// 	log.Fatalf("opening tracing: %s", err)
	// }
	// defer fentry.Close()
	
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
		fmt.Printf("%d %d %s %s %s\n", output.Uid, output.Pid,  output.Command, output.Message, output.Path)
	}
	
}
