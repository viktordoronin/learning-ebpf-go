# Chapter 2

* `hello` - simple example that emits trace messages triggered by a kprobe
* `hello-map` - introduce the concept of a BPF map
* `hello-buffer` - use a perf buffer to pass information to user space
* `hello-tail` - simple demo of eBPF tail calls

## hello-buffer
This one took me a bit to figure out for several reasons:
1.`bpf2go` (the thing that gets executed when you do `go generate`) only looks at BTF info of BPF ELF, so it can miss some things. Do `sudo bpftool btf dump file ./hello_buffer_bpfel.o` to see for yourself. The thing about ring and perf buffers is that they don't care about the data they take so the `__type` attribute in the map definition seems to be entirely unused. Still, this is the only way to get the struct into the BTF and thus have `bpf2go` generate it in the skeleton. I don't think specifying an unused attribute is necessarily a compelling pattern, so here and in subsequent chapters I opt to declare the structure by hand. There's a number of pitfalls you want to avoid, they're described in the comments. 
2.`ebpf/perf` isn't a frequently used package, there isn't a lot of into available on how to use it. The good news is that is that for the userspace program, a perf map looks exactly the same as a ring buffer, so any information regarding userspace usage of `ebpf/ringbuf` will apply here. In this day and age, perf maps are basically obsoleted by ringbuf maps anyway, I only kept perf maps to stay faithful to the original code.

## hello-tail
Here's a description of the program's flow:
1. We create a `BPF_MAP_TYPE_PROG_ARRAY` map. This map is intended to have a function descriptor for each index, so when we call `bpf_tail_call(ctx,array,index)`, `array[index]` evaluates to `func_name()` and `func_name(ctx)` executes as a tail call.
2. In the userspace, we populate our map with function descriptors for each syscall opcode(in our case). There are some explanations in the comments regarding what exactly is done and why.
3. Just like in the original Python example, we first set all opcodes to be ignored and then specify the ones we want to be printed as timer, program execution or something else. However I quickly found out that printing out all the syscalls and all timer operations produce A LOT of output, so I created a new function called `print_syscall()` that allows us to print syscalls selectively. In the userspace, I set it to print syscall 61, so that when you execute `ls` and some other things in a shell you should see an output. The original code for printing stuff is still there, commented out(lines 22, 42). Don't forget to `go generate` to recompile the ELF. 
[Thanks a lot for helping me figure it out!](https://stackoverflow.com/questions/70886166/bpf-tail-call-not-called)
