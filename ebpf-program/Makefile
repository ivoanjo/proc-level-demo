.PHONY: all docker-image ebpf-program clean

BPF_CLANG ?= clang
CFLAGS := -O2 -g -Wall

BPF_CFLAGS := -g -O2 -target bpf -I. -I/usr/include

PKG_CONFIG = pkg-config

all: prctl_vma_loader prctl_vma.bpf.o

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

prctl_vma.bpf.o: prctl_vma.bpf.c vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

prctl_vma_loader: prctl_vma_loader.c
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) -static -o $@ $< $(shell $(PKG_CONFIG) --static --libs libbpf)

clean:
	rm -f *.o prctl_vma_loader vmlinux.h

docker-image:
	docker build -t ebpf-program-build-image -f Dockerfile .

ebpf-program: docker-image
	docker run -v "$$PWD:/app" -it --rm --user $(shell id -u) ebpf-program-build-image:latest make
