# Chronos Kernel eBPF build (Linux 6.2+)
# Requires: clang >= 14, kernel headers, libbpf (for loader)
# Note: target host must match the running kernel arch (x86_64 here).

CLANG      ?= clang
LLC        ?= llc
BPFTOOL    ?= bpftool
KDIR       ?= /lib/modules/$(shell uname -r)/build
ARCH       ?= $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')
CFLAGS     ?= -target bpf -O2 -g -Wall -Wextra \
	      -D__TARGET_ARCH_$(ARCH) \
	      -I$(KDIR)/include -I$(KDIR)/include/asm \
	      -I$(KDIR)/arch/$(shell uname -m)/include -I.

OBJ = chronos_bpf.o

all: $(OBJ)

chronos_bpf.o: chronos_bpf.c
	$(CLANG) $(CFLAGS) -c $< -o $@

# Generate vmlinux.h on the target host (optional; CO-RE build works via BTF):
#   make vmlinux
vmlinux:
	@$(BPFTOOL) btf dump file /boot/vmlinux-$(shell uname -r) format c > vmlinux.h 2>/dev/null || \
	  (echo "bpftool not found; skipping vmlinux.h generation (CO-RE build via /sys/kernel/btf/vmlinux)" && exit 0)

# Loader (userspace, links libbpf)
loader: chronos_loader
chronos_loader: ../loader/chronos_loader.c
	$(CC) $(CFLAGS_HOST) -o $@ ../loader/chronos_loader.c -lbpf 2>/dev/null || \
	  (echo "host cc not available for loader; skipping" && exit 0)

# Unit tests (host-compiled, exercise entropy/magic/classify logic)
test/unit: test/unit.c chronos_core.h
	$(CC) -O2 -g -Wall -Wextra -I. -o $@ test/unit.c -lm

# Integration test: libbpf load + map/program verification (+ best-effort attach)
test/integration: test/integration.c chronos_bpf.o
	$(CC) -O2 -g -Wall -Wextra -I. -o $@ test/integration.c -lbpf

# Systems test: load + attach both kprobes, then tear down
test/systems: test/systems.c chronos_bpf.o
	$(CC) -O2 -g -Wall -Wextra -I. -o $@ test/systems.c -lbpf

# End-to-end test: write to a file, verify ring-buffer capture
test/e2e: test/e2e.c chronos_bpf.o
	$(CC) -O2 -g -Wall -Wextra -I. -o $@ test/e2e.c -lbpf

# Run the full test tier: unit, integration, systems, e2e
test: test/unit test/integration test/systems test/e2e
	@mountpoint -q /sys/fs/bpf 2>/dev/null || mount -t bpf none /sys/fs/bpf 2>/dev/null || true
	@rm -f /sys/fs/bpf/chronos_ringbuf 2>/dev/null || true
	./test/unit
	./test/integration ./chronos_bpf.o
	./test/systems ./chronos_bpf.o
	./test/e2e ./chronos_bpf.o

.PHONY: all loader test test-unit test-integration test-systems test-e2e vmlinux clean

clean:
	rm -f *.o chronos_loader test/unit
