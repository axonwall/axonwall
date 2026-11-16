//go:build ignore
// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
#ifndef __AXONWALL_BPF_MINIMAL_DEFS_H__
#define __AXONWALL_BPF_MINIMAL_DEFS_H__

#include <linux/bpf.h>

#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#ifndef __uint
#define __uint(name, val) int (*name)[val]
#endif

#ifndef __type
#define __type(name, val) typeof(val) *name
#endif

#ifndef NULL
#define NULL ((void *)0)
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif

#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

#define bpf_htons(x) (__builtin_bswap16((__u16)(x)))
#define bpf_ntohs(x) (__builtin_bswap16((__u16)(x)))
#define bpf_htonl(x) (__builtin_bswap32((__u32)(x)))
#define bpf_ntohl(x) (__builtin_bswap32((__u32)(x)))

/* Standard Linux eBPF helper declarations derived from <linux/bpf.h> enum bpf_func_id */
static void *(*const bpf_map_lookup_elem)(void *map, const void *key) =
	(void *)BPF_FUNC_map_lookup_elem;

static long (*const bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) =
	(void *)BPF_FUNC_map_update_elem;

static long (*const bpf_map_delete_elem)(void *map, const void *key) =
	(void *)BPF_FUNC_map_delete_elem;

static __u64 (*const bpf_ktime_get_ns)(void) =
	(void *)BPF_FUNC_ktime_get_ns;

static __u64 (*const bpf_get_current_pid_tgid)(void) =
	(void *)BPF_FUNC_get_current_pid_tgid;

static __u64 (*const bpf_get_current_uid_gid)(void) =
	(void *)BPF_FUNC_get_current_uid_gid;

static long (*const bpf_get_current_comm)(void *buf, __u32 size_of_buf) =
	(void *)BPF_FUNC_get_current_comm;

static long (*const bpf_skb_load_bytes)(const void *skb, __u32 offset, void *to, __u32 len) =
	(void *)BPF_FUNC_skb_load_bytes;

static __u64 (*const bpf_get_socket_cookie)(void *ctx) =
	(void *)BPF_FUNC_get_socket_cookie;

static __u64 (*const bpf_get_current_cgroup_id)(void) =
	(void *)BPF_FUNC_get_current_cgroup_id;

static long (*const bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) =
	(void *)BPF_FUNC_probe_read_user;

static long (*const bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) =
	(void *)BPF_FUNC_probe_read_kernel;

static long (*const bpf_probe_read_user_str)(void *dst, __u32 size, const void *unsafe_ptr) =
	(void *)BPF_FUNC_probe_read_user_str;

static long (*const bpf_probe_read_kernel_str)(void *dst, __u32 size, const void *unsafe_ptr) =
	(void *)BPF_FUNC_probe_read_kernel_str;

static long (*const bpf_ringbuf_output)(void *ringbuf, void *data, __u64 size, __u64 flags) =
	(void *)BPF_FUNC_ringbuf_output;

static void *(*const bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) =
	(void *)BPF_FUNC_ringbuf_reserve;

static void (*const bpf_ringbuf_submit)(void *data, __u64 flags) =
	(void *)BPF_FUNC_ringbuf_submit;

static void (*const bpf_ringbuf_discard)(void *data, __u64 flags) =
	(void *)BPF_FUNC_ringbuf_discard;

#endif /* __AXONWALL_BPF_MINIMAL_DEFS_H__ */
