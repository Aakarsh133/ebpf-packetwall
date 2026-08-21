package bpf

import "C"

//go:generate go tool bpf2go -type ipv4_lpm_key -type ipv6_lpm_key Bpf xdp.c -- -I./headers
