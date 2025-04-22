

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct data_t {     
  __u32 pid;
  __u32 uid;
  char command[16];
  char message[12];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
  //uncomment this to have bpf2go generate the struct inside the skeleton files
  //__type(value, struct data_t);
} output SEC(".maps");

SEC("kprobe")
int hello(void *ctx){
  struct data_t data = {}; 
  char message[12] = "Hello World";
 
  data.pid = bpf_get_current_pid_tgid() >> 32;
  data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   
  bpf_get_current_comm(&data.command, sizeof(data.command));
  bpf_probe_read_kernel(&data.message, sizeof(data.message), message); 

  bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
 
  return 0;
}


