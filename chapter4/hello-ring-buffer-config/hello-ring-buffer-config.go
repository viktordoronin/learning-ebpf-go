//go:generate go run github.com/cilium/ebpf/cmd/bpf2go  ring_config  hello-ring-buffer-config.bpf.c
package main
import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"


	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/link"
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
	var objs ring_configObjects
	if err := loadRing_configObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()
	
	kp, err := link.Kprobe("sys_execve", objs.Hello, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	ringrd, err:=ringbuf.NewReader(objs.Output)
	if err!=nil {
		log.Fatal(err)
	}
	defer ringrd.Close()

	log.Println("Waiting for events..")
	
	var output bpfOutput

	for{
		fmt.Print("entering cycle")
		record, err := ringrd.Read()
		if err != nil {
			panic(err)
		}
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &output); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}
		fmt.Printf("Waiting for read")
		fmt.Printf("%d %d %s %s\n", output.Uid, output.Pid, output.Command, output.Message)
	}
}
