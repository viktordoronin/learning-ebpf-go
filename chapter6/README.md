# Chapter 6
1. BPF program prints some output to trace pipe, however, the original userspace program doesn't read it at any point. I chose to preserve this behaviour; you can read the tracepipe either using Chapter 2 code, or from your shell by using either `sudo cat /sys/kernel/debug/tracing/trace_pipe` or `bpftool prog tracelog`
2. You'll need to compile your C code with debug symbols - this is done with `-g` cflag(already included in `go:generate` directive)
3. Level of logging after successful verifier check is controlled with `LogLevel:1` attribute at line 34; right now the log is set to look like this:
```
probe_exec() verifier log: processed 93 insns (limit 1000000) max_states_per_insn 0 total_states 6 peak_states 6 mark_read 4
XDP_hello() verifier log: processed 7 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
```
change it to `LogLevel:2` to print a full verifier log. In case of verifier rejection, the error is printed starting from line 38.
4. Since one of our programs is XDP, don't forget to turn LRO off if you're executing this under WSL: `ethtool -K eth0 lro off` 

Thanks to [Dylan Reimerink](https://stackoverflow.com/a/76779205) for the code snippet! 
