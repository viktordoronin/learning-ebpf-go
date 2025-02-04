//go:generate go run github.com/cilium/ebpf/cmd/bpf2go hello_tail hello-tail.bpf.c

package main

import(
	"log"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf"

	"github.com/viktordoronin/learning-ebpf-go/helpers"
)

func main() {
    // Remove resource limits for kernels <5.11.
    if err := rlimit.RemoveMemlock(); err != nil { 
        log.Fatal("Removing memlock:", err)
    }
// Load the compiled eBPF ELF and load it into the kernel.
    var objs hello_tailObjects
    if err := loadHello_tailObjects(&objs, nil); err != nil {
        log.Fatal("Loading eBPF objects:", err)
    }
	defer objs.Close()

	// Open a tracepoint and attach the pre-compiled program.
	kp, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name:"sys_enter",Program:objs.Hello})
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer kp.Close()

	// NOTE: we don't have to manually load the other functions like in BCC
	// nor do we have to manually grab a function's file descriptor
	
	// Populate our array so that all opcodes point to ignore_opcode()
	for i:=0;i<500;i++{
		objs.Syscall.Update(uint32(i),uint32(objs.IgnoreOpcode.FD()),ebpf.UpdateAny)
	}

	// set specific opcodes to point to other functions as per original code
	// equivalent to BCC's prog_array[ct.c_int(59)] = ct.c_int(exec_fn.fd) and so on
	// !!! IMPORTANT !!! make the first 2 arguments' sizeofs mimic key_size and value_size for the map you create, that's what uint32() is for
	objs.Syscall.Update(uint32(59),uint32(objs.HelloExec.FD()),ebpf.UpdateAny)
	for i:=222;i<227;i++{
		objs.Syscall.Update(uint32(i),uint32(objs.HelloTimer.FD()),ebpf.UpdateAny)
	}
	objs.Syscall.Update(uint32(61),uint32(objs.PrintSyscall.FD()),ebpf.UpdateAny)

	helpers.Trace_print()
}
