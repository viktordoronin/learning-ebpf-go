# learning-ebpf-go
In this project, I will rewrite [O'Reily's "Learning eBPF" code examples](https://github.com/lizrice/learning-ebpf) into Go, complete with exercises where applicable. Each example is set up as its own package. Run `TODO` to compile everything; to compile an individual example, run `TODO` while inside that folder. Userspace examples are rewritten based on my own expertise and thanks to [ebpf-go documentation](https://github.com/cilium/ebpf?tab=readme-ov-file#packages); eBPF code is rewritten for libbpf based on the book's explanations, considerations from [here](https://facebookmicrosites.github.io/bpf/blog/2020/02/20/bcc-to-libbpf-howto-guide.html) and a bit of information from [here](https://github.com/iovisor/bcc/issues/4404).

# Notes
Chapter 3 contains only eBPF C and thus omitted
Chapter 10 contains no code and thus omitted

# eBPF and Go
Here's a short recap of how to build eBPF programs with Go. This is not an in-depth guide!
1. Set up your module and don't forget to manually add `bpf2go` by running `go get github.com/cilium/ebpf/cmd/bpf2go` in the root of your module;
2. Write your eBPF C code;
3. Run `go generate` to have `bpf2go` build the helpers for your Go code;
4. Write your Go code and run `go build`.

Head [over here](https://ebpf-go.dev/guides/getting-started/) for detailed instructions

# Thanks to:(TODO: add links)

Liz Rice

ebpf-go

myself

# Contact me at:

email

idk what else

# btw hire me pls

# Todo
- Makefile
- go run -exec sudo [./kprobe, ./uretprobe, ./ringbuffer, ...]
