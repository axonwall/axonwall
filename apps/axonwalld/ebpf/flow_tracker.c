//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
};

struct flow_val {
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, struct flow_key);
    __type(value, struct flow_val);
} flow_map SEC(".maps");

SEC("xdp")
int xdp_flow_tracker(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct flow_key key = {};
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.protocol = ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        key.src_port = tcp->source;
        key.dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        key.src_port = udp->source;
        key.dst_port = udp->dest;
    }

    struct flow_val *val = bpf_map_lookup_elem(&flow_map, &key);
    if (val) {
        __sync_fetch_and_add(&val->packets, 1);
        __sync_fetch_and_add(&val->bytes, (data_end - data));
    } else {
        struct flow_val init_val = { .packets = 1, .bytes = (data_end - data) };
        bpf_map_update_elem(&flow_map, &key, &init_val, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
