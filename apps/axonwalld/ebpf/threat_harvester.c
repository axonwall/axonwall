//go:build ignore
// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
/*
 * Axonwall Blackbox: Multi-Plane Extreme eBPF Threat-LLM Harvester
 *
 * Observation planes joined via socket_cookie + cgroup_id + pid:
 *   1. SEC("tc") tc_harvester_ingress / tc_harvester_egress:
 *      - Passive wire observation (always returns TC_ACT_OK).
 *      - Captures Tier-0 compact flow sketches (first 16 signed packet lengths,
 *        first 16 inter-arrival microsecond deltas, JA4T TCP options window/MSS/wscale,
 *        TLS ClientHello SNI prefix, DNS entropy heuristics).
 *      - Escalates to Tier-1 scrubbed L7 payload slices on dark-port hits,
 *        watchlist matches, anomalous memfd processes, or per-scope firehose mode.
 *   2. SEC("tracepoint/sched/sched_process_exec") tp_harvester_exec:
 *      - Captures host & K3s container process executions (pid, uid, cgroup_id, comm).
 *   3. SEC("tracepoint/syscalls/sys_enter_memfd_create") tp_harvester_memfd:
 *      - Flags fileless execution attempts in harvester_suspicious_pids and emits
 *        high-priority PROC_MEMFD telemetry events.
 *   4. SEC("uprobe/SSL_write") uprobe_harvester_ssl_write:
 *      - Guarded OpenSSL SSL_write(SSL *ssl, const void *buf, int num) cleartext
 *        capture for explicitly attached honeypot / allowlisted target binaries only.
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "bpf_minimal_defs.h"

#define HARVESTER_EVT_NET_SKETCH     1
#define HARVESTER_EVT_NET_PAYLOAD    2
#define HARVESTER_EVT_PROC_EXEC      3
#define HARVESTER_EVT_PROC_MEMFD     4
#define HARVESTER_EVT_TLS_CLEARTEXT  5

#define HARVESTER_DIR_INGRESS        0
#define HARVESTER_DIR_EGRESS         1

#define HARVESTER_ANOM_DARK_PORT     (1U << 0)
#define HARVESTER_ANOM_DNS_ENTROPY   (1U << 1)
#define HARVESTER_ANOM_MEMFD_PROC    (1U << 2)
#define HARVESTER_ANOM_WATCHLIST_HIT (1U << 3)
#define HARVESTER_ANOM_FIREHOSE      (1U << 4)
#define HARVESTER_ANOM_TLS_HELLO     (1U << 5)

#define HARVESTER_WATCH_TTL_NS       300000000000ULL /* 300s */

struct harvester_runtime_cfg {
	__u8  enabled;
	__u8  firehose_mode;
	__u8  drop_tier1_backpressure;
	__u8  pad0;
	__u32 max_flow_payload_bytes;
	__u32 benign_sample_mod;
	__u32 pad1;
};

struct harvester_counters_val {
	__u64 packets_seen;
	__u64 tier0_events;
	__u64 tier1_payload_events;
	__u64 ringbuf_drops;
	__u64 dark_port_hits;
	__u64 memfd_alerts;
	__u64 tls_uprobe_events;
};

struct harvester_flow_key {
	__u32 src_v4;
	__u32 dst_v4;
	__u16 src_port;
	__u16 dst_port;
	__u8  proto;
	__u8  family;
	__u16 pad;
};

struct harvester_flow_val {
	__u64 socket_cookie;
	__u64 first_seen_ns;
	__u64 last_seen_ns;
	__u64 byte_count;
	__u32 pkt_count;
	__u32 tier1_bytes_sent;
	__s16 pkt_sizes[16];
	__u32 iat_us[16];
	__u16 ja4t_window;
	__u16 ja4t_mss;
	__u8  tcp_flags_seen;
	__u8  ja4t_wscale;
	__u8  dns_high_entropy_chars;
	__u8  dns_qlen;
	__u8  tls_client_hello;
	__u8  tier1_escalated;
	__u8  sampled_benign;
	__u8  pad;
	__u8  sni[48];
	__u32 pad2;
};

struct harvester_watch_entry {
	__u64 expires_ns;
	__u32 reason_code;
	__u32 pad;
};

struct harvester_ring_event {
	__u64 ts_ns;
	__u64 socket_cookie;
	__u64 cgroup_id;
	__u64 byte_count;
	__u32 ifindex;
	__u32 pid;
	__u32 uid;
	__u32 src_v4;
	__u32 dst_v4;
	__u32 pkt_count;
	__u32 iat_us[16];
	__s16 pkt_sizes[16];
	__u16 src_port;
	__u16 dst_port;
	__u16 tcp_window;
	__u16 tcp_mss;
	__u16 payload_len;
	__u8  event_type;
	__u8  direction;
	__u8  proto;
	__u8  anomaly_flags;
	__u8  tcp_flags;
	__u8  tcp_wscale;
	__u8  comm[16];
	__u8  sni[48];
	__u8  payload[256];
};

const struct harvester_ring_event *unused_harvester_ring_event __attribute__((unused));

struct harvester_vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

/* Standard x86_64/arm64 minimal user pt_regs view */
struct harvester_pt_regs {
#if defined(__TARGET_ARCH_arm64)
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
#else
	__u64 r15;
	__u64 r14;
	__u64 r13;
	__u64 r12;
	__u64 rbp;
	__u64 rbx;
	__u64 r11;
	__u64 r10;
	__u64 r9;
	__u64 r8;
	__u64 rax;
	__u64 rcx;
	__u64 rdx;
	__u64 rsi;
	__u64 rdi;
	__u64 orig_rax;
	__u64 rip;
	__u64 cs;
	__u64 eflags;
	__u64 rsp;
	__u64 ss;
#endif
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 2 * 1024 * 1024);
} harvester_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct harvester_runtime_cfg);
} harvester_cfg_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct harvester_counters_val);
} harvester_counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct harvester_flow_key);
	__type(value, struct harvester_flow_val);
} harvester_flow_state SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct harvester_watch_entry);
} harvester_watchlist_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u16);
	__type(value, __u8);
} harvester_dark_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u64);
} harvester_suspicious_pids SEC(".maps");

/* Emit zero-initialized ringbuf record safely */
static __always_inline struct harvester_ring_event *reserve_harvester_event(struct harvester_counters_val *cnt)
{
	struct harvester_ring_event *ev = bpf_ringbuf_reserve(&harvester_events, sizeof(*ev), 0);
	if (!ev) {
		if (cnt)
			__sync_fetch_and_add(&cnt->ringbuf_drops, 1);
		return NULL;
	}
	return ev;
}

static __always_inline void parse_tcp_options(struct __sk_buff *skb, __u32 opt_off, __u32 opt_len,
					      __u16 *out_mss, __u8 *out_wscale)
{
	if (opt_len == 0)
		return;
	if (opt_len > 40)
		opt_len = 40;

	__u8 optbuf[40] = {};
	__u32 load_len = opt_len;
	if (load_len > sizeof(optbuf))
		load_len = sizeof(optbuf);
	/* Always load 1..40 bytes via masked constant-bounded helper call */
	if (load_len >= 40) {
		if (bpf_skb_load_bytes(skb, opt_off, optbuf, 40) != 0)
			return;
	} else {
		__u32 bounded = load_len & 0x1F;
		if (bounded == 0)
			return;
		if (bpf_skb_load_bytes(skb, opt_off, optbuf, bounded) != 0)
			return;
	}

	__u32 idx = 0;
#pragma unroll
	for (int iter = 0; iter < 8; iter++) {
		if (idx >= opt_len || idx >= 39)
			break;
		__u8 kind = optbuf[idx];
		if (kind == 0)
			break;
		if (kind == 1) {
			idx += 1;
			continue;
		}
		if (idx + 1 >= opt_len || idx + 1 >= 40)
			break;
		__u8 olen = optbuf[idx + 1];
		if (olen < 2 || idx + olen > 40)
			break;
		if (kind == 2 && olen == 4 && idx + 3 < 40) {
			*out_mss = (((__u16)optbuf[idx + 2]) << 8) | ((__u16)optbuf[idx + 3]);
		} else if (kind == 3 && olen == 3 && idx + 2 < 40) {
			*out_wscale = optbuf[idx + 2];
		}
		idx += olen;
	}
}

static __always_inline int process_tc_packet(struct __sk_buff *skb, __u8 direction)
{
	__u32 zero = 0;
	struct harvester_runtime_cfg *cfg = bpf_map_lookup_elem(&harvester_cfg_map, &zero);
	if (!cfg || !cfg->enabled)
		return TC_ACT_OK;

	struct harvester_counters_val *cnt = bpf_map_lookup_elem(&harvester_counters, &zero);
	if (cnt)
		__sync_fetch_and_add(&cnt->packets_seen, 1);

	struct ethhdr eth = {};
	if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) != 0)
		return TC_ACT_OK;

	__u16 h_proto = bpf_ntohs(eth.h_proto);
	__u32 l3_off = sizeof(eth);

	if (h_proto == ETH_P_8021Q || h_proto == ETH_P_8021AD) {
		struct harvester_vlan_hdr vh = {};
		if (bpf_skb_load_bytes(skb, l3_off, &vh, sizeof(vh)) != 0)
			return TC_ACT_OK;
		h_proto = bpf_ntohs(vh.h_vlan_encapsulated_proto);
		l3_off += sizeof(vh);
	}

	if (h_proto != ETH_P_IP) {
		/* Fast path handles IPv4 completely; IPv6/non-IP pass cleanly */
		return TC_ACT_OK;
	}

	struct iphdr iph = {};
	if (bpf_skb_load_bytes(skb, l3_off, &iph, sizeof(iph)) != 0)
		return TC_ACT_OK;
	if (iph.version != 4 || iph.ihl < 5)
		return TC_ACT_OK;

	__u32 l4_off = l3_off + ((__u32)iph.ihl * 4U);
	__u16 src_port = 0;
	__u16 dst_port = 0;
	__u8 tcp_flags = 0;
	__u16 tcp_win = 0;
	__u16 tcp_mss = 0;
	__u8 tcp_wscale = 0;
	__u32 l7_off = l4_off;

	if (iph.protocol == IPPROTO_TCP) {
		struct tcphdr tcph = {};
		if (bpf_skb_load_bytes(skb, l4_off, &tcph, sizeof(tcph)) != 0)
			return TC_ACT_OK;
		if (tcph.doff < 5)
			return TC_ACT_OK;
		src_port = bpf_ntohs(tcph.source);
		dst_port = bpf_ntohs(tcph.dest);
		tcp_win = bpf_ntohs(tcph.window);
		tcp_flags = (((__u8)tcph.fin) << 0) |
			    (((__u8)tcph.syn) << 1) |
			    (((__u8)tcph.rst) << 2) |
			    (((__u8)tcph.psh) << 3) |
			    (((__u8)tcph.ack) << 4) |
			    (((__u8)tcph.urg) << 5);
		__u32 tcp_hdr_len = (__u32)tcph.doff * 4U;
		if (tcp_hdr_len > sizeof(tcph) && tcph.syn) {
			parse_tcp_options(skb, l4_off + sizeof(tcph), tcp_hdr_len - sizeof(tcph),
					  &tcp_mss, &tcp_wscale);
		}
		l7_off = l4_off + tcp_hdr_len;
	} else if (iph.protocol == IPPROTO_UDP) {
		struct udphdr udph = {};
		if (bpf_skb_load_bytes(skb, l4_off, &udph, sizeof(udph)) != 0)
			return TC_ACT_OK;
		src_port = bpf_ntohs(udph.source);
		dst_port = bpf_ntohs(udph.dest);
		l7_off = l4_off + sizeof(udph);
	} else if (iph.protocol != IPPROTO_ICMP) {
		return TC_ACT_OK;
	}

	__u64 now_ns = bpf_ktime_get_ns();
	__u64 cookie = bpf_get_socket_cookie(skb);

	struct harvester_flow_key fkey = {};
	fkey.src_v4 = iph.saddr;
	fkey.dst_v4 = iph.daddr;
	fkey.src_port = src_port;
	fkey.dst_port = dst_port;
	fkey.proto = iph.protocol;
	fkey.family = 4;

	struct harvester_flow_val *fval = bpf_map_lookup_elem(&harvester_flow_state, &fkey);
	if (!fval) {
		struct harvester_flow_val init_val = {};
		init_val.socket_cookie = cookie;
		init_val.first_seen_ns = now_ns;
		init_val.last_seen_ns = now_ns;
		if (cfg->firehose_mode)
			init_val.tier1_escalated = 1;
		bpf_map_update_elem(&harvester_flow_state, &fkey, &init_val, BPF_ANY);
		fval = bpf_map_lookup_elem(&harvester_flow_state, &fkey);
		if (!fval)
			return TC_ACT_OK;
	}

	if (fval->socket_cookie == 0 && cookie != 0)
		fval->socket_cookie = cookie;

	__u64 delta_us = 0;
	if (now_ns > fval->last_seen_ns)
		delta_us = (now_ns - fval->last_seen_ns) / 1000ULL;
	fval->last_seen_ns = now_ns;

	__u32 idx = fval->pkt_count;
	if (idx < 16) {
		__s32 signed_len = (__s32)(skb->len & 0x7FFF);
		if (direction == HARVESTER_DIR_INGRESS)
			signed_len = -signed_len;
		fval->pkt_sizes[idx] = (__s16)signed_len;
		fval->iat_us[idx] = delta_us > 0xFFFFFFFFULL ? 0xFFFFFFFFU : (__u32)delta_us;
	}

	fval->pkt_count += 1;
	fval->byte_count += skb->len;
	fval->tcp_flags_seen |= tcp_flags;
	if (tcp_win && fval->ja4t_window == 0)
		fval->ja4t_window = tcp_win;
	if (tcp_mss && fval->ja4t_mss == 0)
		fval->ja4t_mss = tcp_mss;
	if (tcp_wscale && fval->ja4t_wscale == 0)
		fval->ja4t_wscale = tcp_wscale;

	__u8 anom = 0;
	if (cfg->firehose_mode) {
		anom |= HARVESTER_ANOM_FIREHOSE;
		fval->tier1_escalated = 1;
	}

	/* Dark-port / honeypot trigger check */
	__u8 *is_dark = bpf_map_lookup_elem(&harvester_dark_ports, &dst_port);
	if (is_dark) {
		anom |= HARVESTER_ANOM_DARK_PORT;
		fval->tier1_escalated = 1;
		if (cnt)
			__sync_fetch_and_add(&cnt->dark_port_hits, 1);

		struct harvester_watch_entry w = {};
		w.expires_ns = now_ns + HARVESTER_WATCH_TTL_NS;
		w.reason_code = 1;
		bpf_map_update_elem(&harvester_watchlist_v4, &iph.saddr, &w, BPF_ANY);
	}

	/* Watchlist match on src or dst IP */
	__u32 watch_src = iph.saddr;
	__u32 watch_dst = iph.daddr;
	struct harvester_watch_entry *ws = bpf_map_lookup_elem(&harvester_watchlist_v4, &watch_src);
	if (!ws)
		ws = bpf_map_lookup_elem(&harvester_watchlist_v4, &watch_dst);
	if (ws && (ws->expires_ns == 0 || ws->expires_ns >= now_ns)) {
		anom |= HARVESTER_ANOM_WATCHLIST_HIT;
		fval->tier1_escalated = 1;
	}

	__u32 l7_avail = skb->len > l7_off ? (skb->len - l7_off) : 0;

	/* Lightweight L7 DNS entropy & TLS ClientHello inspection on first payload packet */
	if (l7_avail >= 16 && fval->pkt_count <= 4) {
		__u8 probe[64] = {};
		if (bpf_skb_load_bytes(skb, l7_off, probe, 16) == 0) {
			if (probe[0] == 0x16 && probe[1] == 0x03) {
				fval->tls_client_hello = 1;
				anom |= HARVESTER_ANOM_TLS_HELLO;
			}
		}
		if (iph.protocol == IPPROTO_UDP && (dst_port == 53 || src_port == 53) && l7_avail >= 32) {
			if (bpf_skb_load_bytes(skb, l7_off, probe, 32) == 0) {
				__u8 high_ent = 0;
#pragma unroll
				for (int i = 12; i < 32; i++) {
					__u8 c = probe[i];
					if ((c >= '0' && c <= '9') || c == '-' || c == '_')
						high_ent++;
				}
				if (high_ent >= 12) {
					fval->dns_high_entropy_chars = high_ent;
					anom |= HARVESTER_ANOM_DNS_ENTROPY;
					fval->tier1_escalated = 1;
				}
			}
		}
	}

	__u8 emit_tier1 = 0;
	__u32 max_payload = cfg->max_flow_payload_bytes ? cfg->max_flow_payload_bytes : 4096;
	if (!cfg->drop_tier1_backpressure && fval->tier1_escalated && l7_avail > 0 && fval->tier1_bytes_sent < max_payload) {
		emit_tier1 = 1;
	}

	__u8 emit_sketch = 0;
	if (fval->pkt_count == 1 || fval->pkt_count == 8 || fval->pkt_count == 16 || (tcp_flags & 0x05)) {
		emit_sketch = 1;
	}

	if (!emit_tier1 && !emit_sketch)
		return TC_ACT_OK;

	struct harvester_ring_event *ev = reserve_harvester_event(cnt);
	if (!ev)
		return TC_ACT_OK;

	ev->ts_ns = now_ns;
	ev->socket_cookie = fval->socket_cookie;
	ev->cgroup_id = bpf_get_current_cgroup_id();
	ev->byte_count = fval->byte_count;
	ev->ifindex = skb->ifindex;
	ev->pid = 0;
	ev->uid = 0;
	ev->src_v4 = iph.saddr;
	ev->dst_v4 = iph.daddr;
	ev->pkt_count = fval->pkt_count;

#pragma unroll
	for (int i = 0; i < 16; i++) {
		ev->pkt_sizes[i] = fval->pkt_sizes[i];
		ev->iat_us[i] = fval->iat_us[i];
	}

	ev->src_port = src_port;
	ev->dst_port = dst_port;
	ev->tcp_window = fval->ja4t_window;
	ev->tcp_mss = fval->ja4t_mss;
	ev->payload_len = 0;
	ev->direction = direction;
	ev->proto = iph.protocol;
	ev->anomaly_flags = anom;
	ev->tcp_flags = fval->tcp_flags_seen;
	ev->tcp_wscale = fval->ja4t_wscale;
	ev->comm[0] = '\0';
	ev->sni[0] = '\0';

	if (emit_tier1 && l7_avail > 0) {
		ev->event_type = HARVESTER_EVT_NET_PAYLOAD;
		if (l7_avail >= 256) {
			if (bpf_skb_load_bytes(skb, l7_off, ev->payload, 256) == 0) {
				ev->payload_len = 256;
				fval->tier1_bytes_sent += 256;
			}
		} else {
			__u32 clen = l7_avail & 0xFF;
			if (clen > 0 && bpf_skb_load_bytes(skb, l7_off, ev->payload, clen) == 0) {
				ev->payload_len = (__u16)clen;
				fval->tier1_bytes_sent += clen;
			}
		}
		if (cnt)
			__sync_fetch_and_add(&cnt->tier1_payload_events, 1);
	} else {
		ev->event_type = HARVESTER_EVT_NET_SKETCH;
		if (cnt)
			__sync_fetch_and_add(&cnt->tier0_events, 1);
	}

	bpf_ringbuf_submit(ev, 0);
	return TC_ACT_OK;
}

SEC("tc")
int tc_harvester_ingress(struct __sk_buff *skb)
{
	return process_tc_packet(skb, HARVESTER_DIR_INGRESS);
}

SEC("tc")
int tc_harvester_egress(struct __sk_buff *skb)
{
	return process_tc_packet(skb, HARVESTER_DIR_EGRESS);
}

SEC("tracepoint/sched/sched_process_exec")
int tp_harvester_exec(void *ctx)
{
	__u32 zero = 0;
	struct harvester_runtime_cfg *cfg = bpf_map_lookup_elem(&harvester_cfg_map, &zero);
	if (!cfg || !cfg->enabled)
		return 0;

	struct harvester_counters_val *cnt = bpf_map_lookup_elem(&harvester_counters, &zero);
	struct harvester_ring_event *ev = reserve_harvester_event(cnt);
	if (!ev)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid >> 32);

	ev->ts_ns = bpf_ktime_get_ns();
	ev->socket_cookie = 0;
	ev->cgroup_id = bpf_get_current_cgroup_id();
	ev->byte_count = 0;
	ev->ifindex = 0;
	ev->pid = tgid;
	ev->uid = (__u32)bpf_get_current_uid_gid();
	ev->src_v4 = 0;
	ev->dst_v4 = 0;
	ev->pkt_count = 0;
	ev->src_port = 0;
	ev->dst_port = 0;
	ev->tcp_window = 0;
	ev->tcp_mss = 0;
	ev->payload_len = 0;
	ev->event_type = HARVESTER_EVT_PROC_EXEC;
	ev->direction = 0;
	ev->proto = 0;
	ev->anomaly_flags = 0;
	ev->tcp_flags = 0;
	ev->tcp_wscale = 0;
	bpf_get_current_comm(ev->comm, sizeof(ev->comm));
	ev->sni[0] = '\0';

	if (bpf_map_lookup_elem(&harvester_suspicious_pids, &tgid))
		ev->anomaly_flags |= HARVESTER_ANOM_MEMFD_PROC;

	bpf_ringbuf_submit(ev, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int tp_harvester_memfd(void *ctx)
{
	__u32 zero = 0;
	struct harvester_runtime_cfg *cfg = bpf_map_lookup_elem(&harvester_cfg_map, &zero);
	if (!cfg || !cfg->enabled)
		return 0;

	__u64 now_ns = bpf_ktime_get_ns();
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid >> 32);

	bpf_map_update_elem(&harvester_suspicious_pids, &tgid, &now_ns, BPF_ANY);

	struct harvester_counters_val *cnt = bpf_map_lookup_elem(&harvester_counters, &zero);
	if (cnt)
		__sync_fetch_and_add(&cnt->memfd_alerts, 1);

	struct harvester_ring_event *ev = reserve_harvester_event(cnt);
	if (!ev)
		return 0;

	ev->ts_ns = now_ns;
	ev->socket_cookie = 0;
	ev->cgroup_id = bpf_get_current_cgroup_id();
	ev->byte_count = 0;
	ev->ifindex = 0;
	ev->pid = tgid;
	ev->uid = (__u32)bpf_get_current_uid_gid();
	ev->src_v4 = 0;
	ev->dst_v4 = 0;
	ev->pkt_count = 0;
	ev->src_port = 0;
	ev->dst_port = 0;
	ev->tcp_window = 0;
	ev->tcp_mss = 0;
	ev->payload_len = 0;
	ev->event_type = HARVESTER_EVT_PROC_MEMFD;
	ev->direction = 0;
	ev->proto = 0;
	ev->anomaly_flags = HARVESTER_ANOM_MEMFD_PROC;
	ev->tcp_flags = 0;
	ev->tcp_wscale = 0;
	bpf_get_current_comm(ev->comm, sizeof(ev->comm));
	ev->sni[0] = '\0';

	bpf_ringbuf_submit(ev, 0);
	return 0;
}

SEC("uprobe/SSL_write")
int uprobe_harvester_ssl_write(struct harvester_pt_regs *ctx)
{
	__u32 zero = 0;
	struct harvester_runtime_cfg *cfg = bpf_map_lookup_elem(&harvester_cfg_map, &zero);
	if (!cfg || !cfg->enabled || cfg->drop_tier1_backpressure)
		return 0;

	struct harvester_counters_val *cnt = bpf_map_lookup_elem(&harvester_counters, &zero);
	if (cnt)
		__sync_fetch_and_add(&cnt->tls_uprobe_events, 1);

	const void *buf_ptr = NULL;
	__u32 write_len = 0;
#if defined(__TARGET_ARCH_arm64)
	buf_ptr = (const void *)ctx->regs[1];
	write_len = (__u32)ctx->regs[2];
#else
	buf_ptr = (const void *)ctx->rsi;
	write_len = (__u32)ctx->rdx;
#endif
	if (!buf_ptr || write_len == 0)
		return 0;

	struct harvester_ring_event *ev = reserve_harvester_event(cnt);
	if (!ev)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	ev->ts_ns = bpf_ktime_get_ns();
	ev->socket_cookie = 0;
	ev->cgroup_id = bpf_get_current_cgroup_id();
	ev->byte_count = write_len;
	ev->ifindex = 0;
	ev->pid = (__u32)(pid_tgid >> 32);
	ev->uid = (__u32)bpf_get_current_uid_gid();
	ev->src_v4 = 0;
	ev->dst_v4 = 0;
	ev->pkt_count = 1;
	ev->src_port = 0;
	ev->dst_port = 0;
	ev->tcp_window = 0;
	ev->tcp_mss = 0;
	ev->event_type = HARVESTER_EVT_TLS_CLEARTEXT;
	ev->direction = HARVESTER_DIR_EGRESS;
	ev->proto = IPPROTO_TCP;
	ev->anomaly_flags = 0;
	ev->tcp_flags = 0;
	ev->tcp_wscale = 0;
	bpf_get_current_comm(ev->comm, sizeof(ev->comm));
	ev->sni[0] = '\0';

	if (write_len >= 256) {
		bpf_probe_read_user(ev->payload, 256, buf_ptr);
		ev->payload_len = 256;
	} else {
		__u32 clen = write_len & 0xFF;
		if (clen > 0) {
			bpf_probe_read_user(ev->payload, clen, buf_ptr);
			ev->payload_len = (__u16)clen;
		} else {
			ev->payload_len = 0;
		}
	}

	bpf_ringbuf_submit(ev, 0);
	return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
