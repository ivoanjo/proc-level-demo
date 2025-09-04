// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License (Version 2.0).
// This product includes software developed at Datadog (https://www.datadoghq.com/) Copyright 2025 Datadog, Inc.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "linux/version.h"

#define PR_SET_VMA 0x53564D41
#define PR_SET_VMA_ANON_NAME 0

struct set_vma_anon_name_event {
    __u32 pid;
    __u64 addr;
    __u64 length;
    char name[80];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct prctl_ctx {
    unsigned char skip[16];
    unsigned long option;
    unsigned long arg2;
    unsigned long arg3;
    unsigned long arg4;
    unsigned long arg5;
};

SEC("tracepoint/syscalls/sys_enter_prctl")
int tracepoint__syscalls_sys_enter_prctl(struct prctl_ctx *ctx) {
    unsigned long option = ctx->option;
    unsigned long arg2 = ctx->arg2;
    unsigned long arg3 = ctx->arg3;
    unsigned long arg4 = ctx->arg4;
    unsigned long arg5 = ctx->arg5;
    if (option != PR_SET_VMA || arg2 != PR_SET_VMA_ANON_NAME)
        return 0;

    struct set_vma_anon_name_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->addr = arg3;
    e->length = arg4;

    bpf_probe_read_user_str(e->name, sizeof(e->name), (const void *)arg5);
    bpf_ringbuf_submit(e, 0);
    
    return 0;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = LINUX_VERSION_CODE;
