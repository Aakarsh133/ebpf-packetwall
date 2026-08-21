//go:build ignore

#include "vmlinux.h"
#include "maps.h"
#include <bpf/bpf_helpers.h>

static int parse_ethhdr(struct hdr_cursor *nh, void *data_end, struct ethhdr **ethhdr){

    struct ethhdr *eth = nh->pos;
    int hdrsize = sizeof(*eth);

    if (nh->pos + hdrsize > data_end){
        return -1;
    }

    nh->pos += hdrsize;
    *ethhdr = eth;

    return eth->h_proto;

}

static int parse_ip6hdr(struct hdr_cursor *nh, void *data_end, struct ipv6hdr **ip6hdr){
    struct ipv6hdr *ip6 = nh->pos;
    int hdrsize = sizeof(*ip6);

    if (nh->pos + hdrsize > data_end){
        return -1;
    }

    nh->pos += hdrsize;
    *ip6hdr = ip6;
    return ip6->nexthdr;

}

static int parse_ip4hdr(struct hdr_cursor *nh, void *data_end, struct iphdr **ip4hdr){
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
    int nh_type = parse_ethhdr(&nh, data_end, &eth);

    if (nh_type == -1) goto out;

    else if (nh_type == __builtin_bswap16(ETH_P_IP)){

        struct iphdr *ip4; 
        int ip_proto = parse_ip4hdr(&nh, data_end, &ip4);
        if (ip_proto == -1) goto out;

        __u32 src =  ip4->saddr;

        struct ipv4_lpm_key key = {
            .prefixlen = 32,
            .addr = src
        };

        if (bpf_map_lookup_elem(&ipv4_lpm_map, &key)){
            goto out;
        }

    }
    else if (nh_type == __builtin_bswap16(ETH_P_IPV6)){
        struct ipv6hdr *ip6;
        int ip_proto = parse_ip6hdr(&nh, data_end, &ip6);
        if (ip_proto == -1) goto out;

        __u32 s0 = ip6->saddr.in6_u.u6_addr32[0];
        __u32 s1 = ip6->saddr.in6_u.u6_addr32[1];
        __u32 s2 = ip6->saddr.in6_u.u6_addr32[2];
        __u32 s3 = ip6->saddr.in6_u.u6_addr32[3];

        struct ipv6_lpm_key key = {
            .prefixlen = 128,
            .addr[0] = s0,
            .addr[1] = s1,
            .addr[2] = s2,
            .addr[3] = s3
        };

        if (bpf_map_lookup_elem(&ipv6_lpm_map, &key)){
            goto out;
        }
    }

    return action;
    out:
        action = XDP_DROP;
        return action;
}

char _license[] SEC("license") = "GPL";