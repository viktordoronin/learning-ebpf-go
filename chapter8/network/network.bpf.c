//go:build ignore
#include "network.h"

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
//includes for packet header structs below
#include <linux/if_ether.h>
#include <linux/ip.h>

char __license[] SEC("license") = "GPL";

SEC("kprobe/tcp_v4_connect")
int tcpconnect(void *ctx) {
  bpf_printk("[tcpconnect]\n");
  return 0;
}

SEC("sk_skb")
int socket_filter(struct __sk_buff *skb) {
  /* int cursor = 0; */
  /* struct ethhdr *ethernet; */
  /* int len=sizeof(*ethernet); */
  /* if (skb->len > cursor+len){ */
  /*   bpf_skb_load_bytes(skb, cursor, ethernet, len); */
  /* } */
  /* cursor+=sizeof(*ethernet); */
  /* // Look for IP packets */
  /* if (ethernet->h_proto != 0x0800) { */
  /*   return 0; */
  /* } */

  // Look for IP packets
  if (skb->protocol != 0x0800) {
    return 0;
  }
  
  /* struct iphdr *ip; */
  /* if (skb->len > cursor){ */
  /*   bpf_skb_load_bytes(skb, cursor, ip, sizeof(*ip)); */
  /* } */
  /* cursor+=sizeof(*ip); */
 
  /* if (ip->protocol == 0x01) { */
  /*   bpf_printk("[socket_filter] ICMP request for %x\n", ip->daddr); */
  /* } */

  /* if (ip->protocol == 0x06) { */
  /*   bpf_printk("[socket_filter] TCP packet for %x\n", ip->daddr); */
  /*   // Send TCP packets to userspace */
  /*   return -1; */
  /* } */

  return 0;
}

SEC("xdp")
int myxdp(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  if (is_icmp_ping_request(data, data_end)) {
    struct iphdr *iph = data + sizeof(struct ethhdr);
    struct icmphdr *icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    bpf_printk("[xdp] ICMP request for %x type %x DROPPED\n", iph->daddr,
                     icmp->type);
    return XDP_DROP;
  }

  return XDP_PASS;
}

SEC("tc/ingress")
int tc_drop_ping(struct __sk_buff *skb) {
  bpf_printk("[tc] ingress got packet\n");

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  if (is_icmp_ping_request(data, data_end)) {
    struct iphdr *iph = data + sizeof(struct ethhdr);
    struct icmphdr *icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    bpf_printk("[tc] ICMP request for %x type %x\n", iph->daddr,
                     icmp->type);
    return TC_ACT_SHOT;
  }
  return TC_ACT_OK;
}

SEC("tc")
int tc_drop(struct __sk_buff *skb) {
  bpf_printk("[tc] dropping packet");
  return TC_ACT_SHOT;
}

SEC("tc/ingress")
int tc_pingpong(struct __sk_buff *skb) {
  bpf_printk("[tc] ingress got packet");

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  if (!is_icmp_ping_request(data, data_end)) {
    bpf_printk("[tc] ingress not a ping request");
    return TC_ACT_OK;
  }

  struct iphdr *iph = data + sizeof(struct ethhdr);
  struct icmphdr *icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
  bpf_printk("[tc] ICMP request for %x type %x\n", iph->daddr,
                   icmp->type);

  swap_mac_addresses(skb);
  swap_ip_addresses(skb);

  // Change the type of the ICMP packet to 0 (ICMP Echo Reply) (was 8 for ICMP
  // Echo request)
  update_icmp_type(skb, 8, 0);

  // Redirecting the modified skb on the same interface to be transmitted
  // again
  bpf_clone_redirect(skb, skb->ifindex, 0);

  // We modified the packet and redirected a clone of it, so drop this one
  return TC_ACT_SHOT;
}
