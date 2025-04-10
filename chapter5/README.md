# Chapter 5
(files have been renamed to `hello-buffer-ch5` to prevent conflicts with Chapter 4)
Since we're not using C, `data_t` struct from `hello-buffer-config.h` has been moved to BPF C file. Aside from that, the code is used almost verbatim - `ebpf-go` uses `libbpf` under the hood so all the macros work as is. It didn't work for me initially and I spent 7 hours figuring out why and then it worked and I still have no idea what happened, but that's beside the point. 
Considerations:
1. Be sure to specify a CPU target in your `go generate` directive of your Go file. Currently it's `amd64` since that's what I use, if your CPU is of different architecture you'll need to change it.
2. Dump your `vmlinux.h` with `TODO`. The one that came with the original code didn't work for me, so the one I used might not necessarily work for you.

C code only reads the perf map, so I didn't bother porting it to Go and copied the Chapter 2 code that does the same thing. 
`find-map.go` reads a pinned map. A complementary Bash script to create a map is included(don't forget sudo!), it's the same command that's used in the book 
