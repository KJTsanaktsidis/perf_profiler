#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "stack_sample.bpf.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, STACK_SAMPLE_RINGBUF_SIZE_BYTES);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, STACK_SAMPLE_THREAD_MAP_ENTRIES);
    __type(key, pid_t);
    __type(value, struct stack_sample_thread_data);
} thread_data SEC(".maps");

SEC("perf_event")
int
stack_sample(struct bpf_perf_event_data *ctx)
{
    struct bpf_dynptr event_ptr;
    int r = bpf_ringbuf_reserve_dynptr(&events, sizeof(struct stack_sample_entry), 0, &event_ptr);
    if (r == -1) {
        bpf_ringbuf_discard_dynptr(&event_ptr, 0);
        return -1;
    }

    struct stack_sample_entry *event = bpf_dynptr_data(&event_ptr, 0, sizeof(struct stack_sample_entry));
    if (event == NULL) {
        bpf_ringbuf_discard_dynptr(&event_ptr, 0);
        return -1;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    event->pid = pid_tgid >> 32;
    event->tid = tid;
    event->cpu_id = bpf_get_smp_processor_id();
    event->sample_period = ctx->sample_period;

    struct stack_sample_thread_data *tdata = bpf_map_lookup_elem(&thread_data, &tid);

    bpf_ringbuf_submit_dynptr(&event_ptr, 0);
    return 0;
}
