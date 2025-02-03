//go:generate go run github.com/cilium/ebpf/cmd/bpf2go hello_buffer hello-buffer.bpf.c
package main
import(
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"github.com/cilium/ebpf/link"
  "github.com/cilium/ebpf/rlimit"
  "github.com/cilium/ebpf/perf"
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
	var objs hello_bufferObjects
	if err := loadHello_bufferObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()
	
	kp, err := link.Kprobe("sys_execve", objs.Hello, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	perfrd,err:=perf.NewReader(objs.Output,4096)
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
