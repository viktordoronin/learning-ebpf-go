//go:generate go run github.com/cilium/ebpf/cmd/bpf2go hello-buffer-config hello-buffer-config.bpf.c
package main
func main() {
    // Remove resource limits for kernels <5.11.
    if err := rlimit.RemoveMemlock(); err != nil { 
        log.Fatal("Removing memlock:", err)
    }
// Load the compiled eBPF ELF and load it into the kernel.
    var objs hello-buffer-configObjects
    if err := loadHello-buffer-configObjects(&objs, nil); err != nil {
        log.Fatal("Loading eBPF objects:", err)
    }
    defer objs.Close()
}