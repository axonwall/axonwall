//go:build ignore
// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
/*
 * Axonwall In-Kernel BPF-LSM Preventive Guard & Live CVE Mitigation
 *
 * Integrates the Cloudflare BPF-LSM architecture (TXLF 2026):
 *   1. SEC("lsm/socket_bind") — Copy Fail (CVE-2026-31431) mitigation blocking
 *      untrusted AF_ALG "aead" socket binds (algif_aead page-cache LPE) while
 *      leaving hashes/skciphers untouched.
 *   2. SEC("lsm/bpf") — Restricts sys_bpf(BPF_PROG_LOAD) to executables whose
 *      (s_dev, i_ino) pair is registered in the allowlist map.
 *   3. SEC("lsm/uring_sqpoll") — Blocks zero-syscall io_uring IORING_SETUP_SQPOLL
 *      busy-poll kernel thread creation (Curing / RingReaper rootkits).
 *
 * Every hook respects prior stacked LSM verdicts (`if (ret) return ret;`),
 * identifies calling executables by unspoofable (device, inode) rather than
 * comm, and emits structured denial telemetry over a BPF_MAP_TYPE_RINGBUF.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1
#define AF_ALG 38
#define COMM_LEN 16
#define SALG_TYPE_LEN 14
#define SALG_NAME_LEN 64

#define ALLOW_FLAG_BPF_LOAD    (1U << 0)
#define ALLOW_FLAG_AF_ALG_AEAD (1U << 1)

#define HOOK_ID_SOCKET_BIND_AEAD 1
#define HOOK_ID_BPF_PROG_LOAD    2
#define HOOK_ID_URING_SQPOLL     3

#define POLICY_IDX_ENFORCE_BPF_LOAD    0
#define POLICY_IDX_ENFORCE_URING_SQPOLL 1
#define POLICY_IDX_ENFORCE_COPYFAIL    2

/* Minimal CO-RE kernel structures for BTF relocation */
struct super_block {
	unsigned int s_dev;
} __attribute__((preserve_access_index));

struct inode {
	unsigned long i_ino;
	struct super_block *i_sb;
} __attribute__((preserve_access_index));

struct file {
	struct inode *f_inode;
} __attribute__((preserve_access_index));

struct mm_struct {
	struct file *exe_file;
} __attribute__((preserve_access_index));

struct task_struct {
	struct mm_struct *mm;
} __attribute__((preserve_access_index));

struct sockaddr {
	unsigned short sa_family;
} __attribute__((preserve_access_index));

struct socket {
	void *sk;
} __attribute__((preserve_access_index));

/* Kernel struct sockaddr_alg layout passed to bind(2) for AF_ALG sockets */
struct alg_addr {
	__u16 family;
	char type[SALG_TYPE_LEN];
	__u32 feat;
	__u32 mask;
	char name[SALG_NAME_LEN];
};

/* Unspoofable executable identity: kernel super_block s_dev + inode i_ino */
struct lsm_exe_id {
	__u64 dev;
	__u64 ino;
};

/* Structured ring-buffer event emitted to axonwalld on policy denial */
struct lsm_event {
	__u32 pid;
	__u32 uid;
	__u32 hook_id;
	__u32 blocked;
	__u64 dev;
	__u64 ino;
	char comm[COMM_LEN];
	char detail[SALG_NAME_LEN];
};

const struct lsm_event *unused_lsm_event __attribute__((unused));

static const char aead_type[] = "aead";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, struct lsm_exe_id);
	__type(value, __u8);
} allowlist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u32);
} policy_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 1024);
} events SEC(".maps");

static __always_inline void read_current_exe_id(struct lsm_exe_id *id)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

	id->ino = BPF_CORE_READ(task, mm, exe_file, f_inode, i_ino);
	id->dev = BPF_CORE_READ(task, mm, exe_file, f_inode, i_sb, s_dev);
}

static __always_inline int current_exe_has_flag(__u8 required_flag, struct lsm_exe_id *out_id)
{
	read_current_exe_id(out_id);
	__u8 *flags = bpf_map_lookup_elem(&allowlist, out_id);
	if (!flags)
		return 0;
	return (*flags & required_flag) != 0;
}

static __always_inline int is_policy_enforced(__u32 policy_idx)
{
	__u32 *val = bpf_map_lookup_elem(&policy_config, &policy_idx);
	if (!val)
		return 1; /* Default fail-closed enforcing */
	return *val != 0;
}

static __always_inline void emit_lsm_event(__u32 hook_id, __u32 blocked,
					   const struct lsm_exe_id *id,
					   const char *detail_str, int copy_detail)
{
	struct lsm_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;

	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->hook_id = hook_id;
	e->blocked = blocked;
	e->dev = id->dev;
	e->ino = id->ino;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	__builtin_memset(e->detail, 0, sizeof(e->detail));
	if (copy_detail && detail_str) {
		__builtin_memcpy(e->detail, detail_str, sizeof(e->detail));
		e->detail[sizeof(e->detail) - 1] = '\0';
	}
	bpf_ringbuf_submit(e, 0);
}

/*
 * 1. Copy Fail (CVE-2026-31431) Mitigation:
 * Blocks bind(2) on AF_ALG sockets when alg.type == "aead" unless the
 * calling binary's (s_dev, i_ino) is allowlisted.
 */
SEC("lsm/socket_bind")
int BPF_PROG(copyfail_guard, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
	struct alg_addr alg = {};
	struct lsm_exe_id id = {};

	/* Preserve prior LSM denial verdict */
	if (ret)
		return ret;

	if (!address || address->sa_family != AF_ALG)
		return 0;

	if (addrlen < (int)sizeof(alg))
		return 0;

	if (bpf_probe_read_kernel(&alg, sizeof(alg), address) < 0)
		return 0;

	if (bpf_strncmp(alg.type, sizeof(alg.type), aead_type) != 0)
		return 0;

	if (current_exe_has_flag(ALLOW_FLAG_AF_ALG_AEAD, &id))
		return 0;

	int enforce = is_policy_enforced(POLICY_IDX_ENFORCE_COPYFAIL);
	emit_lsm_event(HOOK_ID_SOCKET_BIND_AEAD, enforce ? 1 : 0, &id, alg.name, 1);

	return enforce ? -EPERM : 0;
}

/*
 * 2. Unauthorized BPF_PROG_LOAD Lockdown:
 * Blocks sys_bpf(BPF_PROG_LOAD) unless the calling binary's (s_dev, i_ino)
 * is present in the allowlist map.
 */
SEC("lsm/bpf")
int BPF_PROG(restrict_bpf_load, int cmd, union bpf_attr *attr, unsigned int size, int ret)
{
	struct lsm_exe_id id = {};
	const char detail[SALG_NAME_LEN] = "BPF_PROG_LOAD";

	if (ret)
		return ret;

	if (cmd != BPF_PROG_LOAD)
		return 0;

	if (current_exe_has_flag(ALLOW_FLAG_BPF_LOAD, &id))
		return 0;

	int enforce = is_policy_enforced(POLICY_IDX_ENFORCE_BPF_LOAD);
	emit_lsm_event(HOOK_ID_BPF_PROG_LOAD, enforce ? 1 : 0, &id, detail, 1);

	return enforce ? -EPERM : 0;
}

/*
 * 3. Syscall-less io_uring SQPOLL Rootkit Mitigation (Curing / RingReaper):
 * Blocks creation of IORING_SETUP_SQPOLL kernel busy-polling threads.
 */
SEC("lsm/uring_sqpoll")
int BPF_PROG(block_uring_sqpoll, int ret)
{
	struct lsm_exe_id id = {};
	const char detail[SALG_NAME_LEN] = "IORING_SETUP_SQPOLL";

	if (ret)
		return ret;

	read_current_exe_id(&id);
	int enforce = is_policy_enforced(POLICY_IDX_ENFORCE_URING_SQPOLL);
	emit_lsm_event(HOOK_ID_URING_SQPOLL, enforce ? 1 : 0, &id, detail, 1);

	return enforce ? -EPERM : 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
