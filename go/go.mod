# Chronos Go Userspace Orchestration Daemon
# Build: cd go && go build -o chronosd .
# Run:   sudo ./chronosd

module chronosd

go 1.22

require (
	github.com/cespare/xxhash/v2 v2.2.0
	golang.org/x/sys v0.17.0
)
