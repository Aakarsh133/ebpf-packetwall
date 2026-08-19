#include "vmlinux.h"
#include "maps.h"
#include <bpf/bpf_helpers.h>

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
    int nh_type = parse_ethhdr(&nh, data_end, &eth);

    if (nh_type == -1) goto out;

    else if (nh_type == bpf_htons(ETH_P_IP)){
        struct iphdr *ip4; 
        int ip_proto = parse_ip4hdr(&nh, data_end, &ip4);
        if (ip_proto == -1) goto out;

        __u32 src =  ip4->saddr;

    }else if (nh_type == bpf_htons(ETH_P_IPV6)){

    }

    return action;
    out:
        action = XDP_DROP;
        return action;
}

char _license[] SEC("license") = "GPL";