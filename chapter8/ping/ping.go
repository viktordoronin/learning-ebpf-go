//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ping ping.bpf.c
package main
import (
	"log"
  "os"
	"io"
	"net"
	
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)
func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil { 
		log.Fatal("Removing memlock:", err)
	}

	var objs pingObjects
	if err:=loadPingObjects(&objs,nil); err!=nil{
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	interf, err := net.InterfaceByName("lo")
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", "lo", err)
	}
	mylink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.Myxdp,
		Interface: interf.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer mylink.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", interf.Name, interf.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")
	
	//BCC trace_print() equivalent
	r,err:=os.Open("/sys/kernel/debug/tracing/trace_pipe")
	if err!=nil{
		log.Fatal(err)
	}
	for{
		_,err=io.Copy(os.Stdout, r)
		if err!=nil{
			log.Fatal(err)
		}
	}
}
