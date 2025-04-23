//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, __u64);
  __type(value, __u64);
} counter_table SEC(".maps");

SEC("kprobe")
int hello(void* ctx){
  __u64 uid;
  __u64 counter = 0;
  __u64 *p;

  uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  p = bpf_map_lookup_elem(&counter_table, &uid);
  if (p != 0) {
    counter = *p;
  }
  counter++;
  bpf_map_update_elem(&counter_table, &uid, &counter, BPF_ANY);
  return 0;
}

//Exercise 2
//I didn't feel like changing it(not like you can change much anyway)
SEC("kprobe")
int hello_o(void* ctx){
  __u64 uid;
  __u64 counter = 0;
  __u64 *p;

  uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  //Exercise 4
  //I actually have no idea how to do this lmao
  p = bpf_map_lookup_elem(&counter_table, &uid);
  if (p != 0) {
    counter = *p;
  }
  counter++;
  bpf_map_update_elem(&counter_table, &uid, &counter, BPF_ANY);
  return 0;
}
