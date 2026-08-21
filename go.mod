module github.com/Aakarsh133/ebpf-packetwall

go 1.26.3

require (
	github.com/cilium/ebpf v0.22.0
	github.com/joho/godotenv v1.5.1
	github.com/praserx/ipconv v1.2.2
)

require golang.org/x/sys v0.43.0 // indirect

tool github.com/cilium/ebpf/cmd/bpf2go
