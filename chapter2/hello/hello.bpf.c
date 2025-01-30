//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

SEC("kprobe")
int hello(void* ctx){
  bpf_printk("Hello World!");
  return 0;
}

char __license[] SEC("license") = "GPL";
