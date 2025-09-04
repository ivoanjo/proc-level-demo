// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License (Version 2.0).
// This product includes software developed at Datadog (https://www.datadoghq.com/) Copyright 2025 Datadog, Inc.

#include <stdio.h>
#include <bpf/libbpf.h>
#include <unistd.h>

struct set_vma_anon_name_event {
    uint32_t pid;
    uint64_t addr;
    uint64_t length;
    char name[64];
};

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct set_vma_anon_name_event *e = data;
    printf("PID %d set anon VMA name: %s (addr: 0x%lx, len: %lu)\n",
           e->pid, e->name, e->addr, e->length);
    return 0;
}

int main() {
    //setenv("LIBBPF_LOG_LEVEL", "debug", 1);
    struct ring_buffer *rb = NULL;
    struct bpf_object *obj;
    int map_fd;

    obj = bpf_object__open_file("prctl_vma.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    int ret = bpf_object__load(obj);
    if (ret) {
        fprintf(stderr, "Error loading BPF object: %d\n", ret);
        return 1;
    
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "tracepoint__syscalls_sys_enter_prctl");
    if (!prog) {
        fprintf(stderr, "Program not found\n");
        return 1;
    }

    struct bpf_link *link = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_prctl");
    if (!link) {
        fprintf(stderr, "Failed to attach tracepoint\n");
        return 1;
    }


    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
    	fprintf(stderr, "Failed to find ringbuf map\n");
    	return 1;
    }
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
    fprintf(stderr, "Failed to create ring buffer\n");
    return 1;
    }

    while (1) {
        ring_buffer__poll(rb, 100);
    }

    return 0;
}

