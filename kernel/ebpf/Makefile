# Chronos Kernel eBPF build (Linux 6.2+)
# Requires: clang >= 14, libbpf headers, kernel headers / vmlinux.h
#   bpftool btf dump file /boot/vmlinux-$(uname -r) format c > vmlinux.h

CLANG      ?= clang
LLC        ?= llc
BPFTOOL    ?= bpftool
KERN_DIR   ?= /lib/modules/$(shell uname -r)/build
CFLAGS     ?= -target bpf -O2 -g -Wall -Wextra \
	      -I$(KERN_DIR)/include -I$(KERN_DIR)/arch/$(shell uname -m)/include \
	      -I. -D__TARGET_ARCH_$(shell uname -m)

OBJ = chronos_bpf.o

all: $(OBJ)

chronos_bpf.o: chronos_bpf.c vmlinux.h
	$(CLANG) $(CFLAGS) -c $< -o $@

# Generate vmlinux.h once (run manually on the target host):
#   make vmlinux
vmlinux:
	$(BPFTOOL) btf dump file /boot/vmlinux-$(shell uname -r) format c > vmlinux.h

load:
	@echo "Use the Go loader or libbpf-based loader to pin chronos_ringbuf"

clean:
	rm -f *.o

.PHONY: all load clean vmlinux
