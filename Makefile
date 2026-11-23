# Chronos top-level build
#
#   make            build kernel eBPF + Go daemon
#   make test       run kernel unit/integration/systems/e2e tests
#   make test-kernel run only the kernel test tier

ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

.PHONY: all test test-kernel kernel go loader clean

all: kernel go

kernel:
	$(MAKE) -C $(ROOT)/kernel/ebpf

loader:
	$(MAKE) -C $(ROOT)/kernel/ebpf loader

go:
	cd $(ROOT)/go && go build -o chronosd .

test: test-kernel

test-kernel:
	$(MAKE) -C $(ROOT)/kernel/ebpf test

clean:
	$(MAKE) -C $(ROOT)/kernel/ebpf clean
	rm -f $(ROOT)/go/chronosd
