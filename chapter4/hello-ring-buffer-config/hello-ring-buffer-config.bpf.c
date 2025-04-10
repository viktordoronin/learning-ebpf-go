//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct data_t {     
   int pid;
   int uid;
   char command[16];
   char message[12];
};

struct user_msg_t {
   char message[12];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, struct user_msg_t);
  __uint(max_entries, 10240);
} config SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4096);
  __type(value, struct data_t);
} output SEC(".maps");

 

SEC("kprobe")
int hello(void *ctx) {
   struct data_t data = {}; 
   char message[12] = "Hello World";
   struct user_msg_t *p;

   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

   bpf_get_current_comm(&data.command, sizeof(data.command));

   p = bpf_map_lookup_elem(&config, &data.uid);
   if (p != 0) {
      bpf_probe_read_kernel(&data.message, sizeof(data.message), p->message);       
   } else {
      bpf_probe_read_kernel(&data.message, sizeof(data.message), message); 
   }

   bpf_ringbuf_output(&output, &data, sizeof(data), 0);
 
   return 0;
}
