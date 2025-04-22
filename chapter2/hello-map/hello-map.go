//go:generate go run github.com/cilium/ebpf/cmd/bpf2go hello_map hello-map.bpf.c
package main
import(
	"fmt"
	"log"
	"github.com/cilium/ebpf/link"
  "github.com/cilium/ebpf/rlimit"
	"time"
)
func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil { 
		log.Fatal("Removing memlock:", err)
	}
	// Load the compiled eBPF ELF and load it into the kernel.
	var objs hello_mapObjects
	if err := loadHello_mapObjects(&objs, nil); err != nil {
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

	//this is a way to continuously read every entry in a hash map
	//as you can see, hash maps aren't too well geared for userspace reading
	for{
		time.Sleep(2*time.Second)
		var s string
		var key, value uint64
		entries:=objs.CounterTable.Iterate()
		for entries.Next(&key,&value){
			s+=fmt.Sprintf("ID %d: %d\t",key,value)
		}
		fmt.Print(s+"\n")
	}
}
