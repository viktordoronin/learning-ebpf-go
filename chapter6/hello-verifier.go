//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cflags -g hello_verifier hello-verifier.bpf.c
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

type bpfOutput struct{
	Pid int32
	Uid int32
	Counter int32
	Command [16]byte
	Message [12]byte
}

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil { 
		log.Fatal("Removing memlock:", err)
	}
	
	// Load the compiled eBPF ELF and load it into the kernel.
	var objs hello_verifierObjects
	//we need to set the log level in the options; change it to 2 for full log
	var opts = ebpf.CollectionOptions{Programs:ebpf.ProgramOptions{LogLevel:1}}
	if err := loadHello_verifierObjects(&objs, &opts); err != nil {
		// log.Fatal("Loading eBPF objects:", err)
		//this bit prints out the full log on error
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			log.Fatalf("%+v\n", verr)
		}
	}
	//these two print out the verifier log once everything is loaded successfully
	fmt.Print("probe_exec() verifier log: ",objs.KprobeExec.VerifierLog)
	fmt.Print("XDP_hello() verifier log: ", objs.XdpHello.VerifierLog)
	defer objs.Close()

	//link.Kprobe() supports ksyscalls too, link in readme
	kp, err := link.Kprobe("sys_execve", objs.KprobeExec, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()
	
	objs.MyConfig.Update(501,"hello Liz",ebpf.UpdateAny)
		
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
		fmt.Printf("%d %d %d %s %s\n", output.Uid, output.Pid, output.Counter, output.Command, output.Message)
	}
	
}
