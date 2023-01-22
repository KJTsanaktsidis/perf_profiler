#ifndef __STACK_SAMPLE__BPF__H
#define __STACK_SAMPLE__BPF__H

#define STACK_SAMPLE_RINGBUF_SIZE_BYTES (256 * 1024)
#define STACK_SAMPLE_THREAD_MAP_ENTRIES 4096

struct stack_sample_entry {
    __u32 pid;
    __u32 tid;
    __u32 cpu_id;
    __u64 sample_period;
};

struct stack_sample_thread_data {
    pid_t pid;
    uintptr_t ruby_cfp_ptr;
    uintptr_t ruby_cfp_base_ptr;
};

#endif

