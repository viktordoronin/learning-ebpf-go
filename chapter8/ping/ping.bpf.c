//go:build ignore
#include "network.h"
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

SEC("xdp")
int myxdp(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  if (is_icmp_ping_request(data, data_end)) {
    bpf_printk("Got ping packet");
    return XDP_DROP;
  }

  return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
