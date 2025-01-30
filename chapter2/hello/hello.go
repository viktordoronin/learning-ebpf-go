//go:generate go run github.com/cilium/ebpf/cmd/bpf2go hello hello.bpf.c
package main

import(
	"log"
	"github.com/cilium/ebpf/link"
  "github.com/cilium/ebpf/rlimit"

	"github.com/viktordoronin/learning-ebpf-go/helpers"
)

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

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. 
	kp, err := link.Kprobe("sys_execve", objs.Hello, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	helpers.Trace_print()
}
