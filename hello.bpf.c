// +build ignore
#include "hello.bpf.h"

struct bpf_map_def SEC("maps") prog_array = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 32,
};

SEC("kprobe/sub_sys_execve")
int sub_hello(void *ctx) {
    bpf_printk("people !\n");
    return 0;
}

SEC("kprobe/sys_execve")
int hello(void *ctx)
{
    u32 id = 1;
    bpf_printk("Hello ");
    bpf_tail_call(ctx, &prog_array, id);
    return 0;
}