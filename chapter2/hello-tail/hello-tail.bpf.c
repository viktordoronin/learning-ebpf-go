//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(key_size, 4);
  __uint(value_size,4);
  __uint(max_entries,500);
} syscall SEC(".maps");


SEC("raw_tracepoint/sys_enter")
int hello(struct bpf_raw_tracepoint_args *ctx) {
  int opcode = ctx->args[1];
  bpf_tail_call(ctx,&syscall,opcode);
  //this was producing way too much output for me so I commented it out in my code
  //bpf_printk("Another syscall: %d", opcode);
  return 0;
}
SEC("raw_tracepoint/sys_enter")
int hello_exec(void *ctx) {
  bpf_printk("Executing a program");
  return 0;
}
SEC("raw_tracepoint/sys_enter")
int hello_timer(struct bpf_raw_tracepoint_args *ctx) {
  int opcode = ctx->args[1];
  switch (opcode) {
  case 222:
    bpf_printk("Creating a timer");
    break;
  case 226:
    bpf_printk("Deleting a timer");
    break;
  default:
    //same story here, this did A LOT of outputs on my system
    //bpf_printk("Some other timer operation");
    break;
  }
  return 0;
}
SEC("raw_tracepoint/sys_enter")
int ignore_opcode(void *ctx) {
  return 0;
}
SEC("raw_tracepoint/sys_enter")
int print_syscall(struct bpf_raw_tracepoint_args *ctx) {
  int opcode = ctx->args[1];
  bpf_printk("Another syscall: %d", opcode);
  return 0;
}
