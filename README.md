# learning-ebpf-go
In this project, I teach myself BPF and Go by rewriting [O'Reily's "Learning eBPF" code examples](https://github.com/lizrice/learning-ebpf) into Go, complete with exercises where applicable. Each example is set up as its own package. ELFs are compiled for you; in order to build the executable, `go build` inside the folder. `go run` won't work since you need root or caps. Userspace examples are rewritten thanks to [ebpf-go documentation](https://pkg.go.dev/github.com/cilium/ebpf) and some stuff I googled(links in their respective chapters); 

BCC code is ported for libbpf based on the book's explanations, considerations from [here](https://facebookmicrosites.github.io/bpf/blog/2020/02/20/bcc-to-libbpf-howto-guide.html) and a bit of information from [here](https://github.com/iovisor/bcc/issues/4404). 

Chapters 3 and 10 are omitted since they contain no userspace code. 

Exercises are done for chapters 2 and 8 since those are the only ones that require actual coding. 

## eBPF and Go
Here's a short recap of how to build eBPF programs with Go. This is not an in-depth guide!
1. Set up your module and don't forget to manually add `bpf2go` by running `go get github.com/cilium/ebpf/cmd/bpf2go` in the root of your module;
2. Write your eBPF C code;
3. Run `go generate` to have `bpf2go` build the helpers for your Go code;
4. Write your Go code and run `go build`.

Head [over here](https://ebpf-go.dev/guides/getting-started/) for detailed instructions.

## Notes, tips and tricks
Just a collection of things that might be useful:
1. You can build everything with `go build ./...` from the root folder. This also works with `go generate` if you need it.
2. If you run into verifier errors, refer to Chapter 6 to see how to get a more verbose error output. Don't forget the `-g` flag!
3. If you want to run an XDP program under WSL or Hyper-V VM, you'll need to turn off LRO on that interface: `ethtool -K eth0 lro off`
4. You can only attach one XDP program to an interface in Linux; if your code crashes after loading the program, the program will remain attached to that interface and will prevent you from loading other programs. `bpftool net detach xdp dev eth0` to unload it manually.
5. You can see the program's BTF information with `bpftool btf dump file ./elf.o`, where `elf.o` is the compiled ELF of your BPF program.

## Thanks to:
- [Liz Rice](https://www.lizrice.com/)
- [ebpf-go](https://github.com/cilium/ebpf)
- Myself

(code snippets and specific solutions are credited in the chapters' readmes)
