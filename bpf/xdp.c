#include "headers/vmlinux.h"
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


struct hdr_cursor{
    void *pos;
};

static __always_inline int parse_ethhdr(struct hdr_cursor *nh, void *data_end, struct ethhdr **ethhdr){

    struct ethhdr *eth = nh->pos;
    int hdrsize = sizeof(*eth);

    if (nh->pos + hdrsize > data_end){
        return -1;
    }

    nh->pos += hdrsize;
    *ethhdr = eth;

    return eth->h_proto;

}

static __always_inline int parse_ip6hdr(struct hdr_cursor *nh, void *data_end, struct ipv6hdr **ip6hdr){
    struct ipv6hdr *ip6 = nh->pos;
    int hdrsize = sizeof(*ip6);

    if (nh->pos + hdrsize > data_end){
        return -1;
    }

    nh->pos += hdrsize;
    *ip6hdr = ip6;
    return ip6->nexthdr;

}

static __always_inline int parse_ip4hdr(struct hdr_cursor *nh, void *data_end, struct iphdr **ip4hdr){
    struct iphdr *ip4 = nh->pos;
    int hdrsize = sizeof(*ip4);

    if (nh->pos + hdrsize > data_end){
        return -1;
    }

    nh->pos += hdrsize;
    *ip4hdr = ip4;
    return ip4->protocol;
}

SEC("xdp")
int xdp_parse_func(struct xdp_md *ctx){
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth;

    __u32 action = XDP_PASS;

    struct hdr_cursor nh;
    nh.pos = data;

    return action;
}

char _license[] SEC("license") = "GPL";