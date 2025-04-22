# Chapter 7
This chapter showcases different types of eBPF programs, and my code showcases how to handle them in Go. Some explanations in the comments.
`bpf2go` makes you load the whole thing at once, so if there's some unsupported programs in the eBPF code, the whole loading process fails. This forced me to comment out the Fentry code as it's not supported on my system.
