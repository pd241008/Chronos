# Chronos top-level build
#
#   make            build kernel eBPF + Go daemon
#   make test       run kernel + Go test tiers (unit/integration/systems/e2e)
#   make test-kernel run only the kernel test tier
#   make test-go    run only the Go test tier

ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

.PHONY: all test test-kernel test-go kernel go loader clean

all: kernel go

kernel:
	$(MAKE) -C $(ROOT)/kernel/ebpf

loader:
	$(MAKE) -C $(ROOT)/kernel/ebpf loader

go:
	cd $(ROOT)/go && go build -o chronosd .

test: test-kernel test-go

test-kernel:
	$(MAKE) -C $(ROOT)/kernel/ebpf test

test-go:
	cd $(ROOT)/go && go test ./... -count=1

clean:
	$(MAKE) -C $(ROOT)/kernel/ebpf clean
	rm -f $(ROOT)/go/chronosd
