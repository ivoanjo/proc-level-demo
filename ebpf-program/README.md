# Description
This is a simple eBPF program meant to hook on prctl tracepoint to demonstrate how that could potentially be done in the profiler.

# Building

```
make ebpf-program
```

# Run

```
sudo ./prctl_vma_loader
```
