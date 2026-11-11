//go:build ignore
// SPDX-License-Identifier: GPL-2.0-only
/*
 * Axonwall XDP Dual-Stack (IPv4/IPv6 + 802.1Q/802.1ad VLAN + IPv6 Ext-Hdr)
 * Flow Tracker, LPM CIDR Prefix Blocker & Line-Rate SYN-Flood PPS Mitigator.
 *
 * Capabilities:
 *   - Peels up to 2 nested IEEE 802.1Q / 802.1ad VLAN tags (recording outer VLAN ID)
 *   - Walks up to 4 IPv6 extension headers (Hop-by-Hop, Routing, Fragment, Dest, Auth)
 *   - Dual-stack IPv4 & IPv6 5-tuple LRU flow tracking (BPF_MAP_TYPE_LRU_HASH)
 *   - Line-rate XDP_DROP exact host blocklist + BPF_MAP_TYPE_LPM_TRIE CIDR subnet
 *     blocklist (IPv4 /8../32 + IPv6 /16../128) with monotonic TTL self-healing
 *   - Per-source 1-second window XDP TCP SYN-flood PPS rate-limiter before sk_buff
 *   - Lockless per-CPU XDP dataplane verdict & protocol telemetry
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif

#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC (1U << 0)
#endif

#ifndef NEXTHDR_HOP
#define NEXTHDR_HOP 0
#endif
#ifndef NEXTHDR_ROUTING
#define NEXTHDR_ROUTING 43
#endif
#ifndef NEXTHDR_FRAGMENT
#define NEXTHDR_FRAGMENT 44
#endif
#ifndef NEXTHDR_AUTH
#define NEXTHDR_AUTH 51
#endif
#ifndef NEXTHDR_DEST
#define NEXTHDR_DEST 60
#endif

struct vlan_hdr_wire {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

struct ipv6_opt_hdr_wire {
	__u8 nexthdr;
	__u8 hdrlen;
};

struct ipv6_frag_hdr_wire {
	__u8  nexthdr;
	__u8  reserved;
	__be16 frag_off;
	__be32 identification;
};

struct flow_key {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u16 vlan_id;
	__u8  protocol;
	__u8  pad;
};

struct flow6_key {
	__u8  src_ip6[16];
	__u8  dst_ip6[16];
	__u16 src_port;
	__u16 dst_port;
	__u16 vlan_id;
	__u8  protocol;
	__u8  pad;
};

struct flow_val {
	__u64 packets;
	__u64 bytes;
	__u64 syn_packets;
	__u64 rst_packets;
	__u64 last_seen_ns;
	__u8  tcp_flags;
	__u8  pad[7];
};

struct ipv6_addr_key {
	__u8 addr[16];
};

struct lpm_v4_key {
	__u32 prefixlen;
	__u32 addr;
};

struct lpm_v6_key {
	__u32 prefixlen;
	__u8  addr[16];
};

struct xdp_block_val {
	__u64 drop_packets;
	__u64 drop_bytes;
	__u64 expires_ns;
	__u32 reason_code;
	__u32 active;
};

struct syn_flood_cfg {
	__u64 max_syn_pps;
	__u32 enabled;
	__u32 pad;
};

struct syn_meter_val {
	__u64 window_start_ns;
	__u64 syn_count;
	__u64 dropped_packets;
};

struct xdp_datastats {
	__u64 rx_packets;
	__u64 rx_bytes;
	__u64 xdp_pass;
	__u64 xdp_drop;
	__u64 ipv4_packets;
	__u64 ipv6_packets;
	__u64 vlan_packets;
	__u64 tcp_syn_packets;
	__u64 lpm_cidr_drops;
	__u64 syn_flood_drops;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 131072);
	__type(key, struct flow_key);
	__type(value, struct flow_val);
} flow_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct flow6_key);
	__type(value, struct flow_val);
} flow6_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 100000);
	__type(key, __u32);
	__type(value, struct xdp_block_val);
} blocklist_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct ipv6_addr_key);
	__type(value, struct xdp_block_val);
} blocklist6_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_v4_key);
	__type(value, struct xdp_block_val);
} cidr_block4_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 32768);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_v6_key);
	__type(value, struct xdp_block_val);
} cidr_block6_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct syn_flood_cfg);
} syn_flood_cfg_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, struct syn_meter_val);
} syn_meter4_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 32768);
	__type(key, struct ipv6_addr_key);
	__type(value, struct syn_meter_val);
} syn_meter6_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct xdp_datastats);
} xdp_stats_map SEC(".maps");

static __always_inline void parse_l4_ports_and_flags(
	void *l4_hdr,
	void *data_end,
	__u8 proto,
	__u16 *src_port,
	__u16 *dst_port,
	__u8 *tcp_flags,
	__u64 *is_syn,
	__u64 *is_rst
) {
	if (proto == IPPROTO_TCP) {
		struct tcphdr *tcp = l4_hdr;
		if ((void *)(tcp + 1) > data_end)
			return;
		*src_port = tcp->source;
		*dst_port = tcp->dest;
		__u8 flags = ((__u8 *)tcp)[13];
		*tcp_flags = flags;
		if ((flags & 0x02) && !(flags & 0x10))
			*is_syn = 1;
		if (flags & 0x04)
			*is_rst = 1;
	} else if (proto == IPPROTO_UDP) {
		struct udphdr *udp = l4_hdr;
		if ((void *)(udp + 1) > data_end)
			return;
		*src_port = udp->source;
		*dst_port = udp->dest;
	}
}

static __always_inline int check_syn_flood_v4(__u32 src_ip, __u64 now_ns)
{
	__u32 cfg_idx = 0;
	struct syn_flood_cfg *cfg = bpf_map_lookup_elem(&syn_flood_cfg_map, &cfg_idx);
	if (!cfg || cfg->enabled == 0 || cfg->max_syn_pps == 0)
		return 0;

	struct syn_meter_val *meter = bpf_map_lookup_elem(&syn_meter4_map, &src_ip);
	if (meter) {
		if (now_ns > meter->window_start_ns && (now_ns - meter->window_start_ns) < 1000000000ULL) {
			__sync_fetch_and_add(&meter->syn_count, 1);
			if (meter->syn_count > cfg->max_syn_pps) {
				__sync_fetch_and_add(&meter->dropped_packets, 1);
				return 1;
			}
			return 0;
		}
		meter->window_start_ns = now_ns;
		meter->syn_count = 1;
		return 0;
	}

	struct syn_meter_val init_m = {};
	init_m.window_start_ns = now_ns;
	init_m.syn_count = 1;
	bpf_map_update_elem(&syn_meter4_map, &src_ip, &init_m, BPF_ANY);
	return 0;
}

static __always_inline int check_syn_flood_v6(struct ipv6_addr_key *src6, __u64 now_ns)
{
	__u32 cfg_idx = 0;
	struct syn_flood_cfg *cfg = bpf_map_lookup_elem(&syn_flood_cfg_map, &cfg_idx);
	if (!cfg || cfg->enabled == 0 || cfg->max_syn_pps == 0)
		return 0;

	struct syn_meter_val *meter = bpf_map_lookup_elem(&syn_meter6_map, src6);
	if (meter) {
		if (now_ns > meter->window_start_ns && (now_ns - meter->window_start_ns) < 1000000000ULL) {
			__sync_fetch_and_add(&meter->syn_count, 1);
			if (meter->syn_count > cfg->max_syn_pps) {
				__sync_fetch_and_add(&meter->dropped_packets, 1);
				return 1;
			}
			return 0;
		}
		meter->window_start_ns = now_ns;
		meter->syn_count = 1;
		return 0;
	}

	struct syn_meter_val init_m = {};
	init_m.window_start_ns = now_ns;
	init_m.syn_count = 1;
	bpf_map_update_elem(&syn_meter6_map, src6, &init_m, BPF_ANY);
	return 0;
}

SEC("xdp")
int xdp_flow_tracker(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	__u64 pkt_len = (__u64)((char *)data_end - (char *)data);

	__u32 stats_idx = 0;
	struct xdp_datastats *stats = bpf_map_lookup_elem(&xdp_stats_map, &stats_idx);
	if (stats) {
		stats->rx_packets++;
		stats->rx_bytes += pkt_len;
	}

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		if (stats)
			stats->xdp_pass++;
		return XDP_PASS;
	}

	__be16 h_proto = eth->h_proto;
	void *nh = (void *)(eth + 1);
	__u16 vlan_id = 0;

	#pragma unroll
	for (int i = 0; i < 2; i++) {
		if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
			struct vlan_hdr_wire *vhdr = nh;
			if ((void *)(vhdr + 1) > data_end) {
				if (stats)
					stats->xdp_pass++;
				return XDP_PASS;
			}
			if (vlan_id == 0)
				vlan_id = bpf_ntohs(vhdr->h_vlan_TCI) & 0x0FFF;
			h_proto = vhdr->h_vlan_encapsulated_proto;
			nh = (void *)(vhdr + 1);
		}
	}

	if (vlan_id != 0 && stats)
		stats->vlan_packets++;

	__u64 now_ns = bpf_ktime_get_ns();

	if (h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = nh;
		if ((void *)(ip + 1) > data_end) {
			if (stats)
				stats->xdp_pass++;
			return XDP_PASS;
		}
		if (stats)
			stats->ipv4_packets++;

		__u32 ihl_bytes = (__u32)ip->ihl * 4;
		if (ihl_bytes < sizeof(struct iphdr) || ihl_bytes > 60) {
			if (stats)
				stats->xdp_pass++;
			return XDP_PASS;
		}
		void *l4 = (void *)ip + ihl_bytes;
		if (l4 > data_end) {
			if (stats)
				stats->xdp_pass++;
			return XDP_PASS;
		}

		__u32 src_ip = ip->saddr;
		struct xdp_block_val *blk = bpf_map_lookup_elem(&blocklist_map, &src_ip);
		if (blk && blk->active == 1) {
			if (blk->expires_ns == 0 || now_ns < blk->expires_ns) {
				__sync_fetch_and_add(&blk->drop_packets, 1);
				__sync_fetch_and_add(&blk->drop_bytes, pkt_len);
				if (stats)
					stats->xdp_drop++;
				return XDP_DROP;
			}
		}

		struct lpm_v4_key lpm4 = { .prefixlen = 32, .addr = src_ip };
		struct xdp_block_val *cblk = bpf_map_lookup_elem(&cidr_block4_map, &lpm4);
		if (cblk && cblk->active == 1) {
			if (cblk->expires_ns == 0 || now_ns < cblk->expires_ns) {
				__sync_fetch_and_add(&cblk->drop_packets, 1);
				__sync_fetch_and_add(&cblk->drop_bytes, pkt_len);
				if (stats) {
					stats->xdp_drop++;
					stats->lpm_cidr_drops++;
				}
				return XDP_DROP;
			}
		}

		struct flow_key key = {};
		key.src_ip = ip->saddr;
		key.dst_ip = ip->daddr;
		key.vlan_id = vlan_id;
		key.protocol = ip->protocol;

		__u8 tcp_flags = 0;
		__u64 is_syn = 0;
		__u64 is_rst = 0;
		parse_l4_ports_and_flags(l4, data_end, ip->protocol, &key.src_port, &key.dst_port, &tcp_flags, &is_syn, &is_rst);

		if (is_syn) {
			if (stats)
				stats->tcp_syn_packets++;
			if (check_syn_flood_v4(src_ip, now_ns)) {
				if (stats) {
					stats->xdp_drop++;
					stats->syn_flood_drops++;
				}
				return XDP_DROP;
			}
		}

		struct flow_val *val = bpf_map_lookup_elem(&flow_map, &key);
		if (val) {
			__sync_fetch_and_add(&val->packets, 1);
			__sync_fetch_and_add(&val->bytes, pkt_len);
			if (is_syn)
				__sync_fetch_and_add(&val->syn_packets, 1);
			if (is_rst)
				__sync_fetch_and_add(&val->rst_packets, 1);
			val->tcp_flags |= tcp_flags;
			val->last_seen_ns = now_ns;
		} else {
			struct flow_val init_val = {};
			init_val.packets = 1;
			init_val.bytes = pkt_len;
			init_val.syn_packets = is_syn;
			init_val.rst_packets = is_rst;
			init_val.last_seen_ns = now_ns;
			init_val.tcp_flags = tcp_flags;
			bpf_map_update_elem(&flow_map, &key, &init_val, BPF_ANY);
		}

		if (stats)
			stats->xdp_pass++;
		return XDP_PASS;
	}

	if (h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = nh;
		if ((void *)(ip6 + 1) > data_end) {
			if (stats)
				stats->xdp_pass++;
			return XDP_PASS;
		}
		if (stats)
			stats->ipv6_packets++;

		struct ipv6_addr_key src6 = {};
		__builtin_memcpy(src6.addr, &ip6->saddr, 16);
		struct xdp_block_val *blk6 = bpf_map_lookup_elem(&blocklist6_map, &src6);
		if (blk6 && blk6->active == 1) {
			if (blk6->expires_ns == 0 || now_ns < blk6->expires_ns) {
				__sync_fetch_and_add(&blk6->drop_packets, 1);
				__sync_fetch_and_add(&blk6->drop_bytes, pkt_len);
				if (stats)
					stats->xdp_drop++;
				return XDP_DROP;
			}
		}

		struct lpm_v6_key lpm6 = { .prefixlen = 128 };
		__builtin_memcpy(lpm6.addr, &ip6->saddr, 16);
		struct xdp_block_val *cblk6 = bpf_map_lookup_elem(&cidr_block6_map, &lpm6);
		if (cblk6 && cblk6->active == 1) {
			if (cblk6->expires_ns == 0 || now_ns < cblk6->expires_ns) {
				__sync_fetch_and_add(&cblk6->drop_packets, 1);
				__sync_fetch_and_add(&cblk6->drop_bytes, pkt_len);
				if (stats) {
					stats->xdp_drop++;
					stats->lpm_cidr_drops++;
				}
				return XDP_DROP;
			}
		}

		__u8 nexthdr = ip6->nexthdr;
		void *l4 = (void *)(ip6 + 1);

		#pragma unroll
		for (int i = 0; i < 4; i++) {
			if (nexthdr == NEXTHDR_HOP || nexthdr == NEXTHDR_ROUTING || nexthdr == NEXTHDR_DEST) {
				struct ipv6_opt_hdr_wire *opt = l4;
				if ((void *)(opt + 1) > data_end)
					break;
				__u32 hdr_bytes = ((__u32)opt->hdrlen + 1) * 8;
				if (hdr_bytes > 256 || (void *)opt + hdr_bytes > data_end)
					break;
				nexthdr = opt->nexthdr;
				l4 = (void *)opt + hdr_bytes;
			} else if (nexthdr == NEXTHDR_FRAGMENT) {
				struct ipv6_frag_hdr_wire *frag = l4;
				if ((void *)(frag + 1) > data_end)
					break;
				nexthdr = frag->nexthdr;
				l4 = (void *)(frag + 1);
			} else if (nexthdr == NEXTHDR_AUTH) {
				struct ipv6_opt_hdr_wire *auth = l4;
				if ((void *)(auth + 1) > data_end)
					break;
				__u32 hdr_bytes = ((__u32)auth->hdrlen + 2) * 4;
				if (hdr_bytes > 256 || (void *)auth + hdr_bytes > data_end)
					break;
				nexthdr = auth->nexthdr;
				l4 = (void *)auth + hdr_bytes;
			}
		}

		struct flow6_key key6 = {};
		__builtin_memcpy(key6.src_ip6, &ip6->saddr, 16);
		__builtin_memcpy(key6.dst_ip6, &ip6->daddr, 16);
		key6.vlan_id = vlan_id;
		key6.protocol = nexthdr;

		__u8 tcp_flags = 0;
		__u64 is_syn = 0;
		__u64 is_rst = 0;
		parse_l4_ports_and_flags(l4, data_end, nexthdr, &key6.src_port, &key6.dst_port, &tcp_flags, &is_syn, &is_rst);

		if (is_syn) {
			if (stats)
				stats->tcp_syn_packets++;
			if (check_syn_flood_v6(&src6, now_ns)) {
				if (stats) {
					stats->xdp_drop++;
					stats->syn_flood_drops++;
				}
				return XDP_DROP;
			}
		}

		struct flow_val *val6 = bpf_map_lookup_elem(&flow6_map, &key6);
		if (val6) {
			__sync_fetch_and_add(&val6->packets, 1);
			__sync_fetch_and_add(&val6->bytes, pkt_len);
			if (is_syn)
				__sync_fetch_and_add(&val6->syn_packets, 1);
			if (is_rst)
				__sync_fetch_and_add(&val6->rst_packets, 1);
			val6->tcp_flags |= tcp_flags;
			val6->last_seen_ns = now_ns;
		} else {
			struct flow_val init_val6 = {};
			init_val6.packets = 1;
			init_val6.bytes = pkt_len;
			init_val6.syn_packets = is_syn;
			init_val6.rst_packets = is_rst;
			init_val6.last_seen_ns = now_ns;
			init_val6.tcp_flags = tcp_flags;
			bpf_map_update_elem(&flow6_map, &key6, &init_val6, BPF_ANY);
		}

		if (stats)
			stats->xdp_pass++;
		return XDP_PASS;
	}

	if (stats)
		stats->xdp_pass++;
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
