//go:build ignore
// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
/*
 * Axonwall In-Kernel BPF-LSM Preventive Guard, Live CVE Mitigation &
 * Linux 6.9+ BPF Token (BPF_TOKEN_CREATE) Ring-0 Delegation Mediator.
 *
 * Integrates Cloudflare BPF-LSM architecture + Linux 6.9+ BPF Token Delegation:
 *   1. SEC("lsm/socket_bind") — Copy Fail (CVE-2026-31431) mitigation blocking
 *      untrusted AF_ALG "aead" socket binds (algif_aead page-cache LPE) while
 *      leaving hashes/skciphers untouched.
 *   2. SEC("lsm/bpf") — Restricts sys_bpf(BPF_PROG_LOAD) to executables whose
 *      (s_dev, i_ino) pair is registered in the host allowlist map, OR to
 *      unprivileged User-Namespaced (CLONE_NEWUSER, user_ns->level > 0)
 *      containers presenting a valid delegated BPF_TOKEN (prog_token_fd > 0)
 *      strictly limited to safe networking program types (XDP, TC, socket_filter,
 *      cgroup_skb) while unconditionally blocking Ring-0 memory/tracing program
 *      types (kprobe, tracepoint, raw_tracepoint, perf_event, tracing, lsm, ext).
 *   3. SEC("lsm/uring_sqpoll") — Blocks zero-syscall io_uring IORING_SETUP_SQPOLL
 *      busy-poll kernel thread creation (Curing / RingReaper rootkits).
 *   4. SEC("lsm/bpf_token_create") — Inspects struct bpf_token bitmasks via CO-RE
 *      when BPF_TOKEN_CREATE is invoked on a delegated bpffs superblock; blocks
 *      token creation (-EPERM) if any kernel-RAM-reading tracing/LSM program bit
 *      was delegated or if minted outside a non-root user namespace.
 *   5. SEC("lsm/bpf_token_cmd") — Mediates and audits token-authorized bpf()
 *      commands across LXC & K3s multi-tenant user namespaces.
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

#define HOOK_ID_SOCKET_BIND_AEAD    1
#define HOOK_ID_BPF_PROG_LOAD       2
#define HOOK_ID_URING_SQPOLL        3
#define HOOK_ID_BPF_TOKEN_DELEGATED 4
#define HOOK_ID_BPF_TOKEN_BLOCKED   5

#define POLICY_IDX_ENFORCE_BPF_LOAD      0
#define POLICY_IDX_ENFORCE_URING_SQPOLL  1
#define POLICY_IDX_ENFORCE_COPYFAIL      2
#define POLICY_IDX_ALLOW_BPF_TOKENS      3
#define POLICY_IDX_AUDIT_BPF_TOKENS      4
#define POLICY_IDX_TOKEN_SAFE_PROGS_LO   5

/*
 * Safe networking BPF program types permitted for delegated UserNS BPF_TOKEN
 * containers (zero arbitrary kernel memory read helpers):
 *   - BPF_PROG_TYPE_SOCKET_FILTER (1)
 *   - BPF_PROG_TYPE_SCHED_CLS (3)
 *   - BPF_PROG_TYPE_SCHED_ACT (4)
 *   - BPF_PROG_TYPE_XDP (6)
 *   - BPF_PROG_TYPE_CGROUP_SKB (8)
 *   - BPF_PROG_TYPE_CGROUP_SOCK (9)
 *   - BPF_PROG_TYPE_LWT_IN..LWT_XMIT (10..12)
 *   - BPF_PROG_TYPE_SOCK_OPS (13)
 *   - BPF_PROG_TYPE_SK_SKB (14)
 *   - BPF_PROG_TYPE_SK_MSG (17)
 *   - BPF_PROG_TYPE_CGROUP_SOCK_ADDR (18)
 *   - BPF_PROG_TYPE_SK_REUSEPORT (21)
 *   - BPF_PROG_TYPE_CGROUP_SOCKOPT (25)
 *   - BPF_PROG_TYPE_SK_LOOKUP (30)
 */
#define DEFAULT_SAFE_TOKEN_PROG_MASK ( \
	(1ULL << BPF_PROG_TYPE_SOCKET_FILTER) | \
	(1ULL << BPF_PROG_TYPE_SCHED_CLS) | \
	(1ULL << BPF_PROG_TYPE_SCHED_ACT) | \
	(1ULL << BPF_PROG_TYPE_XDP) | \
	(1ULL << BPF_PROG_TYPE_CGROUP_SKB) | \
	(1ULL << BPF_PROG_TYPE_CGROUP_SOCK) | \
	(1ULL << BPF_PROG_TYPE_SOCK_OPS) | \
	(1ULL << BPF_PROG_TYPE_SK_SKB) | \
	(1ULL << BPF_PROG_TYPE_SK_MSG) | \
	(1ULL << BPF_PROG_TYPE_CGROUP_SOCK_ADDR) | \
	(1ULL << BPF_PROG_TYPE_SK_REUSEPORT) | \
	(1ULL << BPF_PROG_TYPE_CGROUP_SOCKOPT) | \
	(1ULL << 30) | \
	(1ULL << 32) \
)

/*
 * Ring-0 tracing, introspection & kernel-modification program types that expose
 * bpf_probe_read_kernel(), fentry/kprobe arbitrary symbol attachment, or LSM
 * policy tampering. Strictly forbidden inside delegated container BPF tokens!
 */
#define FORBIDDEN_RING0_TOKEN_PROG_MASK ( \
	(1ULL << BPF_PROG_TYPE_KPROBE) | \
	(1ULL << BPF_PROG_TYPE_TRACEPOINT) | \
	(1ULL << BPF_PROG_TYPE_PERF_EVENT) | \
	(1ULL << BPF_PROG_TYPE_RAW_TRACEPOINT) | \
	(1ULL << BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE) | \
	(1ULL << BPF_PROG_TYPE_TRACING) | \
	(1ULL << BPF_PROG_TYPE_STRUCT_OPS) | \
	(1ULL << BPF_PROG_TYPE_EXT) | \
	(1ULL << BPF_PROG_TYPE_LSM) | \
	(1ULL << BPF_PROG_TYPE_SYSCALL) \
)

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

struct user_namespace {
	int level;
} __attribute__((preserve_access_index));

struct cred {
	struct user_namespace *user_ns;
} __attribute__((preserve_access_index));

struct task_struct {
	struct mm_struct *mm;
	const struct cred *cred;
} __attribute__((preserve_access_index));

struct bpf_token {
	struct user_namespace *userns;
	__u64 allowed_cmds;
	__u64 allowed_maps;
	__u64 allowed_progs;
	__u64 allowed_attachs;
} __attribute__((preserve_access_index));

struct path;

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

/* Structured ring-buffer event emitted to axonwalld on policy denial or token audit */
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
	__uint(max_entries, 8);
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

static __always_inline int read_current_userns_level(void)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	return BPF_CORE_READ(task, cred, user_ns, level);
}

static __always_inline int current_exe_has_flag(__u8 required_flag, struct lsm_exe_id *out_id)
{
	read_current_exe_id(out_id);
	__u8 *flags = bpf_map_lookup_elem(&allowlist, out_id);
	if (!flags)
		return 0;
	return (*flags & required_flag) != 0;
}

static __always_inline int is_policy_enabled(__u32 policy_idx, int default_val)
{
	__u32 *val = bpf_map_lookup_elem(&policy_config, &policy_idx);
	if (!val)
		return default_val;
	return *val != 0;
}

static __always_inline __u64 get_safe_token_prog_mask(void)
{
	__u32 idx = POLICY_IDX_TOKEN_SAFE_PROGS_LO;
	__u32 *custom_lo = bpf_map_lookup_elem(&policy_config, &idx);
	if (custom_lo && *custom_lo != 0)
		return ((__u64)(*custom_lo)) & ~FORBIDDEN_RING0_TOKEN_PROG_MASK;
	return DEFAULT_SAFE_TOKEN_PROG_MASK;
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

	int enforce = is_policy_enabled(POLICY_IDX_ENFORCE_COPYFAIL, 1);
	emit_lsm_event(HOOK_ID_SOCKET_BIND_AEAD, enforce ? 1 : 0, &id, alg.name, 1);

	return enforce ? -EPERM : 0;
}

/*
 * 2. BPF_PROG_LOAD Lockdown + Linux 6.9+ Delegated BPF_TOKEN Mediation:
 * Permits host (s_dev, i_ino) allowlisted loaders (axonwalld, bpftool) AND
 * unprivileged User-Namespaced containers (user_ns->level > 0) holding a
 * delegated BPF_TOKEN (prog_token_fd > 0) for safe networking program types.
 * Strictly blocks Ring-0 tracing/rootkit program types regardless of token.
 */
SEC("lsm/bpf")
int BPF_PROG(restrict_bpf_load, int cmd, union bpf_attr *attr, unsigned int size, int ret)
{
	struct lsm_exe_id id = {};

	if (ret)
		return ret;

	if (cmd != BPF_PROG_LOAD)
		return 0;

	if (current_exe_has_flag(ALLOW_FLAG_BPF_LOAD, &id))
		return 0;

	/* Inspect prog_type and prog_token_fd for Linux 6.9+ BPF_TOKEN delegation */
	__u32 prog_type = 0;
	__s32 prog_token_fd = 0;
	if (attr) {
		bpf_probe_read_kernel(&prog_type, sizeof(prog_type), attr);
		if (size >= __builtin_offsetof(union bpf_attr, prog_token_fd) + sizeof(__s32)) {
			bpf_probe_read_kernel(
				&prog_token_fd,
				sizeof(prog_token_fd),
				(const char *)attr + __builtin_offsetof(union bpf_attr, prog_token_fd)
			);
		}
	}

	if (prog_token_fd > 0 && is_policy_enabled(POLICY_IDX_ALLOW_BPF_TOKENS, 1)) {
		int userns_level = read_current_userns_level();
		__u64 prog_bit = (prog_type < 64) ? (1ULL << prog_type) : 0;
		__u64 safe_mask = get_safe_token_prog_mask();

		if (userns_level > 0 && prog_bit != 0 &&
		    (prog_bit & FORBIDDEN_RING0_TOKEN_PROG_MASK) == 0 &&
		    (prog_bit & safe_mask) != 0) {
			if (is_policy_enabled(POLICY_IDX_AUDIT_BPF_TOKENS, 1)) {
				const char ok_detail[SALG_NAME_LEN] = "BPF_TOKEN_DELEGATED_NET_PROG";
				emit_lsm_event(HOOK_ID_BPF_TOKEN_DELEGATED, 0, &id, ok_detail, 1);
			}
			return 0;
		}

		const char tok_deny[SALG_NAME_LEN] = "BPF_TOKEN_FORBIDDEN_RING0_PROG";
		int enforce_tok = is_policy_enabled(POLICY_IDX_ENFORCE_BPF_LOAD, 1);
		emit_lsm_event(HOOK_ID_BPF_TOKEN_BLOCKED, enforce_tok ? 1 : 0, &id, tok_deny, 1);
		return enforce_tok ? -EPERM : 0;
	}

	const char detail[SALG_NAME_LEN] = "BPF_PROG_LOAD";
	int enforce = is_policy_enabled(POLICY_IDX_ENFORCE_BPF_LOAD, 1);
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
	int enforce = is_policy_enabled(POLICY_IDX_ENFORCE_URING_SQPOLL, 1);
	emit_lsm_event(HOOK_ID_URING_SQPOLL, enforce ? 1 : 0, &id, detail, 1);

	return enforce ? -EPERM : 0;
}

/*
 * 4. Linux 6.9+ BPF_TOKEN_CREATE Superblock Bitmask Guard:
 * Inspects token->allowed_progs and token->userns->level via CO-RE when a
 * container calls bpf(BPF_TOKEN_CREATE). Blocks minting tokens whose bpffs
 * mount accidentally delegated Ring-0 tracing/LSM program types or init_user_ns.
 */
SEC("lsm/bpf_token_create")
int BPF_PROG(guard_bpf_token_create, struct bpf_token *token, union bpf_attr *attr,
	     const struct path *path, int ret)
{
	struct lsm_exe_id id = {};

	if (ret)
		return ret;

	read_current_exe_id(&id);

	if (!is_policy_enabled(POLICY_IDX_ALLOW_BPF_TOKENS, 1)) {
		const char dis_detail[SALG_NAME_LEN] = "BPF_TOKEN_CREATE_POLICY_DISABLED";
		emit_lsm_event(HOOK_ID_BPF_TOKEN_BLOCKED, 1, &id, dis_detail, 1);
		return -EPERM;
	}

	__u64 allowed_progs = BPF_CORE_READ(token, allowed_progs);
	int ns_level = BPF_CORE_READ(token, userns, level);

	if (ns_level <= 0) {
		const char ns_detail[SALG_NAME_LEN] = "BPF_TOKEN_CREATE_INIT_USERNS_DENIED";
		emit_lsm_event(HOOK_ID_BPF_TOKEN_BLOCKED, 1, &id, ns_detail, 1);
		return -EPERM;
	}

	if ((allowed_progs & FORBIDDEN_RING0_TOKEN_PROG_MASK) != 0) {
		const char unsafe_detail[SALG_NAME_LEN] = "BPF_TOKEN_CREATE_UNSAFE_TRACING_MASK";
		emit_lsm_event(HOOK_ID_BPF_TOKEN_BLOCKED, 1, &id, unsafe_detail, 1);
		return -EPERM;
	}

	if (is_policy_enabled(POLICY_IDX_AUDIT_BPF_TOKENS, 1)) {
		const char ok_detail[SALG_NAME_LEN] = "BPF_TOKEN_CREATE_MINTED";
		emit_lsm_event(HOOK_ID_BPF_TOKEN_DELEGATED, 0, &id, ok_detail, 1);
	}

	return 0;
}

/*
 * 5. Linux 6.9+ BPF_TOKEN Command Mediator:
 * Verifies every token-backed bpf() command at execution time against
 * FORBIDDEN_RING0_TOKEN_PROG_MASK and active token delegation policy.
 */
SEC("lsm/bpf_token_cmd")
int BPF_PROG(audit_bpf_token_cmd, const struct bpf_token *token, enum bpf_cmd cmd, int ret)
{
	struct lsm_exe_id id = {};

	if (ret)
		return ret;

	if (!is_policy_enabled(POLICY_IDX_ALLOW_BPF_TOKENS, 1)) {
		read_current_exe_id(&id);
		const char dis_detail[SALG_NAME_LEN] = "BPF_TOKEN_CMD_POLICY_DISABLED";
		emit_lsm_event(HOOK_ID_BPF_TOKEN_BLOCKED, 1, &id, dis_detail, 1);
		return -EPERM;
	}

	__u64 allowed_progs = BPF_CORE_READ(token, allowed_progs);
	if ((allowed_progs & FORBIDDEN_RING0_TOKEN_PROG_MASK) != 0) {
		read_current_exe_id(&id);
		const char unsafe_detail[SALG_NAME_LEN] = "BPF_TOKEN_CMD_UNSAFE_PROGS";
		emit_lsm_event(HOOK_ID_BPF_TOKEN_BLOCKED, 1, &id, unsafe_detail, 1);
		return -EPERM;
	}

	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
