#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_ENTRIES 100000

struct ipv4_lpm_key{
    __u32 prefixlen;
    __u32 addr;
};

struct ipv6_lpm_key{
    __u32 prefixlen;
    __u32 addr[4];
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, MAX_ENTRIES);
} ipv4_lpm_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv6_lpm_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, MAX_ENTRIES);
} ipv6_lpm_map SEC(".maps");

