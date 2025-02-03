# Chapter 2

* `hello.py` - simple example that emits trace messages triggered by a kprobe
* `hello-map.py` - introduce the concept of a BPF map
* `hello-buffer.py` - use a ring buffer to convey information to user space
* `hello-tail.py` - simple demo of eBPF tail calls

## hello-buffer
Oh boy... This one took me a while to figure out. `go generate` doesn't create a `struct` that mirrors your kernelspace structure so you have to create it yourself, which creates A LOT of room for error. Plenty on that in the comments. On top of that, `ebpf/perf` isn't super well documented; however, there's only one thing you really have to understand and that is that for the userspace program, a perf map looks exactly the same as a ring buffer, so any information regarding the usage of `ebpf/ringbuf` will apply here. [The ringbuffer example](https://github.com/cilium/ebpf/tree/main/examples/ringbuffer) ended up being of tremendous help.
