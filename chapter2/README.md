# Chapter 2

* `hello.py` - simple example that emits trace messages triggered by a kprobe
* `hello-map.py` - introduce the concept of a BPF map
* `hello-buffer.py` - use a ring buffer to convey information to user space
* `hello-tail.py` - simple demo of eBPF tail calls

## hello-buffer
Oh boy... This one took me a while to figure out. `go generate` doesn't create a `struct` that mirrors your kernelspace structure so you have to create it yourself, which creates A LOT of room for error. Plenty on that in the comments. On top of that, `ebpf/perf` isn't super well documented; however, there's only one thing you really have to understand and that is that for the userspace program, a perf map looks exactly the same as a ring buffer, so any information regarding the usage of `ebpf/ringbuf` will apply here. [The ringbuffer example](https://github.com/cilium/ebpf/tree/main/examples/ringbuffer) ended up being of tremendous help.

## hello-tail
The book didn't make things too obvious(for me, at least), so here's a description of the program's flow:
1. We create a `BPF_MAP_TYPE_PROG_ARRAY` map. This map is intended to have a function descriptor for each index, so that when we call `bpf_tail_call(ctx,array,index)`, where `array[index]==func_name()` it executes `func_name(ctx)` as a tail call.
2. In the userspace, we populate our map with function descriptors for each syscall opcode(in our case). There are some explanations in the comments regarding what exactly is done and why.
3. Just like in the original Python example, we first set all opcodes to be ignored and then specify the ones we want to be printed as timer, program execution or something else. However I quickly found out that printing out all the syscalls and all timer operations produce A LOT of output, so I created a new function called `print_syscall()` that allows us to print syscalls selectively. In the userspace, I set it to print syscall 61, so that when you execute `ls` and some other things in a shell you should see an output. 
