import {
  HostMalwareDefenseConfigSchema,
  type DesiredState,
  type HostMalwareDefenseConfig,
} from '../../schemas/index.js';

export interface HostMalwareScannerSpec {
  id: string;
  name: string;
  binary: string;
  category: 'classic_scanner' | 'fim_audit' | 'ring0_telemetry' | 'kernel_lockdown';
  layer: 'userspace' | 'ring0_kcore' | 'silicon_pmu' | 'lsm_enforcement';
  description: string;
  defaultCommand: string;
  detects: string[];
}

export const HOST_MALWARE_SCANNERS: HostMalwareScannerSpec[] = [
  {
    id: 'rkhunter',
    name: 'Rootkit Hunter (rkhunter)',
    binary: 'rkhunter',
    category: 'classic_scanner',
    layer: 'userspace',
    description:
      'Scans for 400+ known rootkits, hidden files, suspicious kernel symbol strings, /dev anomalies, and binary SHA-256 property drift.',
    defaultCommand: 'rkhunter --check --sk --rwo',
    detects: ['Diamorphine', 'Reptile', 'Adore-ng', 'Suterusu', 'Trojaned /bin binaries', '/dev SHM implants'],
  },
  {
    id: 'chkrootkit',
    name: 'Check Rootkit (chkrootkit)',
    binary: 'chkrootkit',
    category: 'classic_scanner',
    layer: 'userspace',
    description:
      'Audits system binaries for LKM rootkit hooks, LD_PRELOAD hijacks (ldsopreload), promiscuous NICs, and wtmp/utmp/lastlog log wiping.',
    defaultCommand: 'chkrootkit -q',
    detects: ['LD_PRELOAD userland rootkits', 'Hidden LKM modules', 'Promiscuous packet sniffers', 'Log wipers (z2/wted)'],
  },
  {
    id: 'clamav',
    name: 'ClamAV Antivirus Engine (clamscan)',
    binary: 'clamscan',
    category: 'classic_scanner',
    layer: 'userspace',
    description:
      'Multi-threaded signature and heuristic antivirus engine scanning /tmp, /dev/shm, /var/tmp, /etc, and /root for ELF trojans, droppers, and webshells.',
    defaultCommand: 'clamscan --infected --recursive /tmp /var/tmp /dev/shm /etc/cron*',
    detects: ['Linux ELF trojans', 'Cryptominers (XMRig)', 'Webshells', 'Ransomware payloads'],
  },
  {
    id: 'aide',
    name: 'AIDE Cryptographic File Integrity (FIM)',
    binary: 'aide',
    category: 'fim_audit',
    layer: 'userspace',
    description:
      'Verifies SHA-512 + inode/xattr/ACL cryptographic baseline across /bin, /sbin, /usr/bin, /usr/sbin, /lib/modules, and /etc/axonwall.',
    defaultCommand: 'aide --check --config=/etc/aide/aide.conf',
    detects: ['Trojaned system binaries', 'Unauthorized kernel modules (.ko)', 'Modified PAM / sshd configs'],
  },
  {
    id: 'lynis',
    name: 'Lynis Security & CIS Hardening Auditor',
    binary: 'lynis',
    category: 'fim_audit',
    layer: 'userspace',
    description:
      'Performs deep host security auditing across kernel sysctls, systemd units, PAM modules, cron persistence, and MAC frameworks.',
    defaultCommand: 'lynis audit system --quick --no-colors',
    detects: ['Weak sysctl posture', 'Rogue systemd persistence units', 'Insecure SSH/PAM configurations'],
  },
  {
    id: 'yara',
    name: 'YARA Ghost-in-the-Ring Implant Scanner',
    binary: 'yara',
    category: 'classic_scanner',
    layer: 'userspace',
    description:
      'Matches custom YARA rules against memory/disk artifacts for TripleCross, Boopkit, Symbiote, BPFDoor, Curing, and RingReaper implants.',
    defaultCommand: 'yara -r /etc/axonwall/yara/ghost_in_the_ring.yar /tmp /dev/shm /var/tmp',
    detects: ['TripleCross eBPF rootkit', 'Boopkit', 'Symbiote', 'BPFDoor', 'Curing io_uring implant', 'RingReaper'],
  },
  {
    id: 'unhide',
    name: 'Unhide Forensic Process & Port Hunter',
    binary: 'unhide',
    category: 'classic_scanner',
    layer: 'userspace',
    description:
      'Brute-forces PID space and cross-compares /proc against sysinfo(), getpriority(), sched_getaffinity(), and kill(pid,0) to expose cloaked tasks.',
    defaultCommand: 'unhide sys proc',
    detects: ['getdents64-cloaked PIDs', 'Hidden threads', 'Unlisted TCP/UDP covert listeners'],
  },
  {
    id: 'debsums',
    name: 'Debian Package Checksum Verifier (debsums)',
    binary: 'debsums',
    category: 'fim_audit',
    layer: 'userspace',
    description:
      'Validates installed ELF binaries and libraries on disk against official Debian dpkg cryptographic digests.',
    defaultCommand: 'debsums -s',
    detects: ['Tampered libc/libpam shared objects', 'Replaced /usr/bin utilities'],
  },
  {
    id: 'io-uring-ring-hunter',
    name: 'Ghost-in-the-Ring: io_uring SQPOLL & Fixed-File Hunter',
    binary: 'hunt-io-uring-implants.sh',
    category: 'ring0_telemetry',
    layer: 'ring0_kcore',
    description:
      'Enumerates anon_inode:[io_uring] descriptors across /proc/[pid]/fdinfo to catch syscall-less Curing/RingReaper implants using IORING_SETUP_SQPOLL (SqThread != -1) or IOSQE_FIXED_FILE.',
    defaultCommand: '/usr/local/bin/hunt-io-uring-implants.sh',
    detects: ['Curing io_uring rootkit', 'RingReaper post-exploitation agent', 'Zero-syscall IORING_SETUP_SQPOLL C2 rings'],
  },
  {
    id: 'drgn-kcore-prog-idr',
    name: 'Ghost-in-the-Ring: /proc/kcore prog_idr XArray Auditor',
    binary: 'audit_hidden_bpf_prog_idr.py',
    category: 'ring0_telemetry',
    layer: 'ring0_kcore',
    description:
      'Walks the kernel prog_idr radix/XArray directly in /proc/kcore via drgn and diffs against sys_bpf(BPF_PROG_GET_NEXT_ID) to catch self-hiding eBPF rootkits.',
    defaultCommand: 'drgn /usr/local/bin/audit_hidden_bpf_prog_idr.py',
    detects: ['Self-hiding eBPF programs', 'BPF_PROG_GET_NEXT_ID spoofing', 'Cloaked fexit/__x64_sys_bpf hooks'],
  },
  {
    id: 'pmu-lbr-trampoline-auditor',
    name: 'Ghost-in-the-Ring: Silicon PMU LBR / BRS Branch Auditor',
    binary: 'hunt-ebpf-rootkits.sh',
    category: 'ring0_telemetry',
    layer: 'silicon_pmu',
    description:
      'Uses CPU Performance Monitoring Unit Last Branch Records (Intel LBR / AMD BRS) and bpftool bytecode inspection to catch hidden bpf_trampoline jumps and Helper #36/#58 abuse.',
    defaultCommand: '/usr/local/bin/hunt-ebpf-rootkits.sh',
    detects: ['bpf_probe_write_user (#36) tampering', 'bpf_override_return (#58)', 'Covert XDP_DROP C2 triggers', 'Hidden fentry/fexit trampolines'],
  },
  {
    id: 'bpf-lsm-lockdown',
    name: 'Ghost-in-the-Ring: Preventive BPF_LSM & Lockdown Policy',
    binary: 'bpftool',
    category: 'kernel_lockdown',
    layer: 'lsm_enforcement',
    description:
      'Enforces SEC("lsm/bpf") inode allowlisting for BPF_PROG_LOAD, SEC("lsm/uring_sqpoll") -EPERM blocking, kernel.io_uring_disabled, and lockdown=confidentiality.',
    defaultCommand: 'sysctl kernel.io_uring_disabled kernel.unprivileged_bpf_disabled',
    detects: ['Unauthorized BPF_PROG_LOAD', 'Rogue IORING_SETUP_SQPOLL creation', 'Unprivileged eBPF exploitation'],
  },
];

export interface IoUringInstanceReport {
  pid: number;
  comm: string;
  fd: number;
  sqThread: number;
  sqThreadCpu: number;
  sqHead: number;
  sqTail: number;
  cqHead: number;
  cqTail: number;
  userFiles: number;
  sqPollActive: boolean;
  fixedFilesActive: boolean;
  severity: 'INFO' | 'HIGH' | 'CRITICAL';
  reasons: string[];
}

export interface KcoreBpfProgEntry {
  id: number;
  type: string;
  name: string;
  expectedAttachType?: string;
}

export interface HiddenEbpfDiffResult {
  kcoreIds: number[];
  userspaceIds: number[];
  hiddenIds: number[];
  hiddenPrograms: KcoreBpfProgEntry[];
  compromised: boolean;
  severity: 'CLEAN' | 'CRITICAL';
  summary: string;
}

export interface BpfBytecodeAuditFinding {
  progId?: number;
  progName?: string;
  helperOrHook: string;
  severity: 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  mitreTechnique: string;
}

export interface PmuLbrTrampolineHit {
  comm: string;
  pid: number;
  fromSymbol: string;
  toSymbol: string;
  severity: 'HIGH' | 'CRITICAL';
  description: string;
}

export function resolveHostDefenseConfig(state?: Partial<DesiredState> | null): HostMalwareDefenseConfig {
  return HostMalwareDefenseConfigSchema.parse(state?.hostDefense ?? {});
}

/**
 * Generates /etc/sysctl.d/99-axonwall-ghost-in-the-ring.conf to harden io_uring, eBPF JIT,
 * and kernel pointer / ptrace exposure.
 */
export function compileKernelHardeningSysctl(state?: Partial<DesiredState> | null): string {
  const cfg = resolveHostDefenseConfig(state);
  return [
    '# =============================================================================',
    '# Axonwall Ghost-in-the-Ring Kernel Rootkit & io_uring Lockdown',
    '# Generated by @axonwall/lib/compile/rootkit',
    '# =============================================================================',
    '',
    '# Layer 1: Restrict or Disable io_uring (CVE-2023-2598 / Curing / RingReaper mitigation)',
    '# 0 = enabled for all, 1 = restricted to io_uring_group GID, 2 = disabled system-wide',
    `kernel.io_uring_disabled = ${cfg.ioUringDisabledMode}`,
    `kernel.io_uring_group = ${cfg.ioUringAllowedGid}`,
    '',
    '# Layer 2: Disable unprivileged eBPF & harden BPF JIT constant blinding',
    `kernel.unprivileged_bpf_disabled = ${cfg.unprivilegedBpfDisabled ? 1 : 0}`,
    `net.core.bpf_jit_harden = ${cfg.bpfJitHardenMode}`,
    '',
    '# Layer 3: Kernel symbol, dmesg, and ptrace anti-reconnaissance hardening',
    'kernel.kptr_restrict = 2',
    'kernel.dmesg_restrict = 1',
    'kernel.yama.ptrace_scope = 2',
    '',
  ].join('\n');
}

/**
 * Generates the preventive BPF_LSM C source program that:
 * 1. Hooks SEC("lsm/bpf") to block BPF_PROG_LOAD unless the calling task's executable inode
 *    is present in the pinned `trusted_bpf_loaders` allowlist map.
 * 2. Hooks SEC("lsm/uring_sqpoll") to return -EPERM and prevent zero-syscall IORING_SETUP_SQPOLL
 *    kernel busy-polling threads system-wide.
 */
export function compileBpfLsmGuardC(state?: Partial<DesiredState> | null): string {
  const cfg = resolveHostDefenseConfig(state);
  const trustedPathsComment = cfg.trustedBpfLoaderPaths
    .map((p) => ` *   - ${String(p).replace(/[\r\n]+/g, '')}`)
    .join('\n');
  const sqpollReturn = cfg.blockIoUringSqpoll ? '-EPERM' : '0';

  return `// SPDX-License-Identifier: GPL-2.0
// =============================================================================
// Axonwall Ghost-in-the-Ring Preventive BPF_LSM Lockdown Guard
// Requires boot parameter: lsm=landlock,lockdown,yama,integrity,apparmor,bpf
// Recommended kernel lockdown mode: lockdown=${cfg.kernelLockdownMode}
// Trusted BPF Loader Binaries (populate inode numbers in trusted_bpf_loaders):
${trustedPathsComment}
// =============================================================================
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1

char LICENSE[] SEC("license") = "GPL";

// Map of allowed executable inodes permitted to call BPF_PROG_LOAD
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, u64);   // Executable inode number (i_ino)
    __type(value, u8);  // 1 = allowed
} trusted_bpf_loaders SEC(".maps");

SEC("lsm/bpf")
int BPF_PROG(restrict_bpf_load, int cmd, union bpf_attr *attr, unsigned int size)
{
    if (cmd != BPF_PROG_LOAD)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 ino = BPF_CORE_READ(task, mm, exe_file, f_inode, i_ino);

    u8 *allowed = bpf_map_lookup_elem(&trusted_bpf_loaders, &ino);
    if (!allowed) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        bpf_printk("AXONWALL_LSM_BLOCK: unauthorized BPF_PROG_LOAD pid=%d ino=%llu\\n", pid, ino);
        return -EPERM;
    }

    return 0;
}

// Block io_uring SQPOLL zero-syscall kernel thread creation system-wide
SEC("lsm/uring_sqpoll")
int BPF_PROG(block_uring_sqpoll)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("AXONWALL_LSM_BLOCK: io_uring IORING_SETUP_SQPOLL denied for pid=%d\\n", pid);
    return ${sqpollReturn};
}
`;
}

/**
 * Generates /usr/local/bin/audit_hidden_bpf_prog_idr.py which walks the kernel's internal
 * `prog_idr` radix tree / XArray in `/proc/kcore` via `drgn` and diffs it against
 * `bpftool prog show --json` (`sys_bpf(BPF_PROG_GET_NEXT_ID)`) to expose self-hiding eBPF rootkits.
 */
export function compileDrgnProgIdrAuditScript(): string {
  return `#!/usr/bin/env drgn
# =============================================================================
# Axonwall Ghost-in-the-Ring: Out-of-Band /proc/kcore prog_idr Auditor
# Usage: sudo drgn /usr/local/bin/audit_hidden_bpf_prog_idr.py
# =============================================================================
# Compares the kernel's internal prog_idr radix tree / XArray in /proc/kcore
# against userspace sys_bpf(BPF_PROG_GET_NEXT_ID) (bpftool prog show --json)
# to expose self-hiding eBPF rootkits (TripleCross, Boopkit, Symbiote).
# =============================================================================

import json
import subprocess
from drgn.helpers.linux.idr import idr_for_each

# 1. Enumerate BPF program IDs visible to standard userspace sys_bpf()
userspace_ids = set()
try:
    out = subprocess.check_output(["bpftool", "-j", "prog", "show"], stderr=subprocess.DEVNULL)
    for p in json.loads(out.decode("utf-8")):
        if "id" in p:
            userspace_ids.add(int(p["id"]))
except Exception:
    pass

# 2. Walk the true Ring-0 prog_idr XArray directly from /proc/kcore
kcore_ids = set()
print(f"{'ID':<8} {'TYPE':<26} {'NAME':<24} {'VISIBILITY'}")
print("-" * 76)

for prog_id, ptr in idr_for_each(prog["prog_idr"].address_of_()):
    bpf_prog = drgn.Object(prog, "struct bpf_prog *", value=ptr)
    prog_type = bpf_prog.type.format_(type_name=False)
    aux_name = bpf_prog.aux.name.string_().decode("utf-8", "replace")
    kcore_ids.add(int(prog_id))

    if int(prog_id) not in userspace_ids and len(userspace_ids) > 0:
        status = "CRITICAL: HIDDEN FROM SYS_BPF (ROOTKIT)"
    else:
        status = "VISIBLE"

    print(f"{prog_id:<8} {prog_type:<26} {aux_name:<24} {status}")

hidden = sorted(kcore_ids - userspace_ids) if userspace_ids else []
if hidden:
    print(f"\\n[!] ALERT: Detected {len(hidden)} hidden eBPF program(s) in prog_idr: {hidden}")
else:
    print(f"\\n[+] OK: All {len(kcore_ids)} Ring-0 prog_idr entries match userspace sys_bpf().")
`;
}

/**
 * Generates /usr/local/bin/hunt-io-uring-implants.sh to scan live /proc/[pid]/fdinfo
 * for anon_inode:[io_uring] rings, IORING_SETUP_SQPOLL threads, and IOSQE_FIXED_FILE descriptors.
 */
export function compileIoUringHuntScript(): string {
  return `#!/usr/bin/env bash
# =============================================================================
# Axonwall Ghost-in-the-Ring: Live io_uring Implant & SQPOLL Hunter
# Scans /proc/[pid]/fd and /proc/[pid]/fdinfo for anon_inode:[io_uring]
# =============================================================================
set -euo pipefail

echo "=== [1] Kernel io_uring Lockdown Sysctl Status ==="
sysctl kernel.io_uring_disabled kernel.io_uring_group 2>/dev/null || true

echo -e "\\n=== [2] Scanning /proc for Active anon_inode:[io_uring] Rings ==="
FOUND=0
for fd_path in /proc/[0-9]*/fd/*; do
  if [[ -L "$fd_path" ]]; then
    target=$(readlink "$fd_path" 2>/dev/null || true)
    if [[ "$target" == "anon_inode:[io_uring]" ]]; then
      FOUND=$((FOUND + 1))
      pid=$(echo "$fd_path" | cut -d'/' -f3)
      fd=$(echo "$fd_path" | cut -d'/' -f5)
      comm=$(cat "/proc/$pid/comm" 2>/dev/null || echo "unknown")
      exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")
      echo "[!] Active io_uring ring -> PID: $pid ($comm) | EXE: $exe | FD: $fd"
      grep -E "SqThread|SqThreadCpu|SqHead|SqTail|CqHead|CqTail|UserFiles" "/proc/$pid/fdinfo/$fd" 2>/dev/null | sed 's/^/    /' || true
    fi
  fi
done

if [[ "$FOUND" -eq 0 ]]; then
  echo "[+] Clean: Zero active anon_inode:[io_uring] rings found across /proc."
fi

echo -e "\\n=== [3] Checking Kernel Threads for io-wq / iou-sqp Busy-Poll Workers ==="
ps -ef | grep -E "\\[iou-sqp-|\\[io-wq-" | grep -v grep || echo "[+] Clean: No io_uring SQPOLL kernel threads active."
`;
}

/**
 * Generates /usr/local/bin/hunt-ebpf-rootkits.sh to hunt offensive eBPF rootkits
 * via dmesg kernel taint warnings, /sys/kernel/tracing/enabled_functions,
 * bpftool xlated bytecode inspection for Helper #36/#58, and Silicon PMU LBR branch stacks.
 */
export function compileEbpfRootkitHuntScript(): string {
  return `#!/usr/bin/env bash
# =============================================================================
# Axonwall Ghost-in-the-Ring: Live eBPF Rootkit & Hardware PMU LBR Triage
# =============================================================================
set -euo pipefail

echo "=== [1] Checking Kernel Taint & Offensive BPF Helper Warnings ==="
cat /proc/sys/kernel/tainted 2>/dev/null || true
dmesg 2>/dev/null | grep -iE "bpf_probe_write_user|bpf_override_return|taint" | tail -n 20 || echo "[+] No dmesg helper warnings."

echo -e "\\n=== [2] Inspecting Ftrace / Trampoline Hooks on Critical Syscalls ==="
if [[ -r /sys/kernel/tracing/enabled_functions ]]; then
  grep -E "bpf_trampoline|__x64_sys_(getdents|bpf|read|kill| clone)|tcp4_seq_show" /sys/kernel/tracing/enabled_functions || echo "[+] No suspicious ftrace trampolines found."
else
  echo "[i] /sys/kernel/tracing/enabled_functions not readable or debugfs not mounted."
fi

echo -e "\\n=== [3] Auditing Loaded eBPF Programs & XDP/TC Attachments ==="
if command -v bpftool >/dev/null 2>&1; then
  bpftool prog show || true
  bpftool net show || true

  echo -e "\\n=== [4] Scanning eBPF Bytecode for Helper #36 (bpf_probe_write_user) & Helper #58 (bpf_override_return) ==="
  for id in $(bpftool prog show | awk -F: '/^[0-9]+:/ {print $1}'); do
    if bpftool prog dump xlated id "$id" 2>/dev/null | grep -qE "bpf_probe_write_user|bpf_override_return"; then
      echo "[!] CRITICAL: Program ID $id invokes offensive memory-patching helper!"
      bpftool prog show id "$id" || true
    fi
  done
else
  echo "[i] bpftool not installed."
fi

echo -e "\\n=== [5] Sampling Silicon Hardware PMU Last Branch Records (Intel LBR / AMD BRS) ==="
if command -v perf >/dev/null 2>&1; then
  mkdir -p -m 0700 /run/axonwall
  perf record -e branches:k -j any,k -a -o /run/axonwall/axonwall-lbr.data -- sleep 1 >/dev/null 2>&1 && \\
    perf script -i /run/axonwall/axonwall-lbr.data --fields comm,pid,brstacksym 2>/dev/null | grep -E "bpf_trampoline|bpf_prog_" | head -n 20 || \\
    echo "[+] No unexpected PMU LBR jumps into bpf_trampoline detected (or PMU LBR unsupported in VM)."
  rm -f /run/axonwall/axonwall-lbr.data
else
  echo "[i] linux-perf not installed."
fi
`;
}

/**
 * Generates /etc/axonwall/yara/ghost_in_the_ring.yar with signature rules for
 * TripleCross, Boopkit, Symbiote, BPFDoor, Curing (io_uring), and RingReaper.
 */
export function compileYaraGhostInTheRingRules(): string {
  return `// =============================================================================
// Axonwall Ghost-in-the-Ring YARA Rule Pack
// Targets: TripleCross, Boopkit, Symbiote, BPFDoor, Curing, RingReaper
// =============================================================================

rule Linux_eBPF_Rootkit_TripleCross_Boopkit {
    meta:
        author = "Axonwall Security Engineering"
        severity = "CRITICAL"
        description = "Detects offensive eBPF rootkits abusing bpf_probe_write_user (#36) and getdents64/sys_bpf hooks"
    strings:
        $h1 = "bpf_probe_write_user" ascii
        $h2 = "bpf_override_return" ascii
        $s1 = "tp/syscalls/sys_exit_getdents64" ascii
        $s2 = "fexit/__x64_sys_bpf" ascii
        $s3 = "TripleCross" ascii nocase
        $s4 = "boopkit" ascii nocase
    condition:
        uint32(0) == 0x464c457f and ((1 of ($h*) and 1 of ($s*)) or 2 of ($s*))
}

rule Linux_IoUring_Implant_Curing_RingReaper {
    meta:
        author = "Axonwall Security Engineering"
        severity = "CRITICAL"
        description = "Detects syscall-less io_uring implants (Curing / RingReaper) utilizing SQPOLL and FIXED_FILE"
    strings:
        $u1 = "io_uring_queue_init_params" ascii
        $u2 = "io_uring_register_files" ascii
        $u3 = "anon_inode:[io_uring]" ascii
        $c1 = "RingReaper" ascii nocase
        $c2 = "IORING_SETUP_SQPOLL" ascii
    condition:
        uint32(0) == 0x464c457f and (all of ($u1, $u2) or 1 of ($c*) or ($u1 and $u3))
}

rule Linux_Stealth_Backdoor_BPFDoor_Symbiote {
    meta:
        author = "Axonwall Security Engineering"
        severity = "CRITICAL"
        description = "Detects BPFDoor classic/eBPF magic packet filters and Symbiote LD_PRELOAD/BPF hooks"
    strings:
        $b1 = { 72 55 00 00 } // Classic BPFDoor magic TCP/UDP trigger bytes
        $b2 = "hald-addon-acpi" ascii
        $b3 = "HIDE_THIS_SHELL" ascii
        $b4 = "symbiote" ascii nocase
    condition:
        uint32(0) == 0x464c457f and 1 of ($b*)
}
`;
}

/**
 * Generates /etc/rkhunter.conf.local and the unified /usr/local/bin/axonwall-hunt-rootkits CLI runner.
 */
export function compileRkhunterConfig(state?: Partial<DesiredState> | null): {
  rkhunterConfLocal: string;
  cronScheduleFile: string;
  unifiedRunnerScript: string;
} {
  const cfg = resolveHostDefenseConfig(state);
  if (!/^[0-9*,/-]+\s+[0-9*,/-]+\s+[0-9*,/-]+\s+[0-9*,/-]+\s+[0-9*,/-]+$/.test(cfg.scheduledScanCron)) {
    throw new Error(`Invalid scheduledScanCron expression: ${cfg.scheduledScanCron}`);
  }

  const rkhunterConfLocal = [
    '# =============================================================================',
    '# Axonwall Rootkit Hunter (rkhunter) Local Hardening Configuration',
    '# File: /etc/rkhunter.conf.local',
    '# =============================================================================',
    'MIRRORS_MODE=0',
    'UPDATE_MIRRORS=1',
    'WEB_CMD=""',
    'AUTO_X_DETECT=1',
    'ALLOW_SSH_ROOT_USER=no',
    'ALLOW_SSH_PROT_V1=0',
    'ENABLE_TESTS=ALL',
    'DISABLE_TESTS=suspscan,deleted_files',
    'HASH_CMD=SHA256',
    'PKGMGR=DPKG',
    'ALLOWDEVFILE=/dev/shm/axonwall-*',
    'SYSLOG_ON_WARNING=1',
    '',
  ].join('\n');

  const cronScheduleFile = [
    '# =============================================================================',
    '# Axonwall Automated Host Malware, Rootkit & Ring-0 Implant Audit Schedule',
    '# File: /etc/cron.d/axonwall-host-defense',
    '# =============================================================================',
    'SHELL=/bin/bash',
    'PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin',
    `${cfg.scheduledScanCron} root /usr/local/bin/axonwall-hunt-rootkits --scheduled >> /var/log/axonwall-rootkit-hunt.log 2>&1`,
    '',
  ].join('\n');

  const unifiedRunnerScript = `#!/usr/bin/env bash
# =============================================================================
# Axonwall Unified Host Malware, Rootkit & Ghost-in-the-Ring Kernel Hunter
# Executes classic scanners (rkhunter, chkrootkit, clamscan, aide, lynis, yara,
# unhide, debsums) + Ring-0 io_uring & eBPF rootkit telemetry checks.
# =============================================================================
set -uo pipefail

echo "============================================================================="
echo " AXONWALL HOST MALWARE, ROOTKIT & GHOST-IN-THE-RING KERNEL AUDIT"
echo " Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "============================================================================="

if [[ "${cfg.rkhunterEnabled}" == "true" ]] && command -v rkhunter >/dev/null 2>&1; then
  echo -e "\\n>>> [1/9] Running Rootkit Hunter (rkhunter)..."
  rkhunter --check --sk --rwo || true
fi

if [[ "${cfg.chkrootkitEnabled}" == "true" ]] && command -v chkrootkit >/dev/null 2>&1; then
  echo -e "\\n>>> [2/9] Running Check Rootkit (chkrootkit)..."
  chkrootkit -q || true
fi

if [[ "${cfg.unhideEnabled}" == "true" ]] && command -v unhide >/dev/null 2>&1; then
  echo -e "\\n>>> [3/9] Running Unhide Forensic Process Hunter..."
  unhide sys proc || true
fi

if [[ "${cfg.yaraEnabled}" == "true" ]] && command -v yara >/dev/null 2>&1 && [[ -f /etc/axonwall/yara/ghost_in_the_ring.yar ]]; then
  echo -e "\\n>>> [4/9] Running YARA Ghost-in-the-Ring Signature Scan..."
  yara -r /etc/axonwall/yara/ghost_in_the_ring.yar /tmp /dev/shm /var/tmp 2>/dev/null || true
fi

if [[ "${cfg.aideEnabled}" == "true" ]] && command -v aide >/dev/null 2>&1 && [[ -f /var/lib/aide/aide.db ]]; then
  echo -e "\\n>>> [5/9] Running AIDE Cryptographic File Integrity Check..."
  aide --check --config=/etc/aide/aide.conf || true
fi

if [[ "${cfg.lynisEnabled}" == "true" ]] && command -v lynis >/dev/null 2>&1; then
  echo -e "\\n>>> [6/9] Running Lynis CIS & Host Hardening Audit..."
  lynis audit system --quick --no-colors || true
fi

if [[ "${cfg.clamavEnabled}" == "true" ]] && command -v clamscan >/dev/null 2>&1; then
  echo -e "\\n>>> [7/9] Running ClamAV Malware & Trojan Scan..."
  clamscan --infected --recursive /tmp /var/tmp /dev/shm || true
fi

if [[ -x /usr/local/bin/hunt-io-uring-implants.sh ]]; then
  echo -e "\\n>>> [8/9] Running Ghost-in-the-Ring io_uring Implant & SQPOLL Hunter..."
  /usr/local/bin/hunt-io-uring-implants.sh || true
fi

if [[ -x /usr/local/bin/hunt-ebpf-rootkits.sh ]]; then
  echo -e "\\n>>> [9/9] Running Ghost-in-the-Ring eBPF Rootkit & PMU LBR Auditor..."
  /usr/local/bin/hunt-ebpf-rootkits.sh || true
fi

echo -e "\\n[+] Axonwall Host Malware & Kernel Rootkit Hunt Completed."
`;

  return {
    rkhunterConfLocal,
    cronScheduleFile,
    unifiedRunnerScript,
  };
}

/**
 * Parses `/proc/[pid]/fdinfo/[fd]` content for an `anon_inode:[io_uring]` descriptor
 * and flags `IORING_SETUP_SQPOLL` (`SqThread != -1`) or `IOSQE_FIXED_FILE` (`UserFiles > 0`).
 */
export function parseIoUringFdInfo(
  pid: number,
  comm: string,
  fd: number,
  fdInfoText: string,
  trustedComms: string[] = ['haproxy', 'nginx', 'clickhouse', 'postgres', 'qemu-system-x86']
): IoUringInstanceReport {
  const getInt = (key: string, fallback = 0): number => {
    const match = fdInfoText.match(new RegExp(`^${key}:\\s*(-?\\d+)`, 'm'));
    return match ? parseInt(match[1], 10) : fallback;
  };

  const sqThread = getInt('SqThread', -1);
  const sqThreadCpu = getInt('SqThreadCpu', -1);
  const sqHead = getInt('SqHead', 0);
  const sqTail = getInt('SqTail', 0);
  const cqHead = getInt('CqHead', 0);
  const cqTail = getInt('CqTail', 0);
  const userFiles = getInt('UserFiles', 0);

  const sqPollActive = sqThread !== -1;
  const fixedFilesActive = userFiles > 0;
  const isTrusted = trustedComms.includes(comm);

  const reasons: string[] = [];
  let severity: 'INFO' | 'HIGH' | 'CRITICAL' = 'INFO';

  if (sqPollActive) {
    severity = 'CRITICAL';
    reasons.push(
      `IORING_SETUP_SQPOLL active (kernel thread SqThread=${sqThread} on CPU ${sqThreadCpu}): allows zero-syscall ring I/O completely invisible to sys_enter tracepoints.`
    );
  }
  if (fixedFilesActive && !isTrusted) {
    if (severity !== 'CRITICAL') severity = 'HIGH';
    reasons.push(
      `IOSQE_FIXED_FILE table registered (${userFiles} pre-registered private file descriptors): allows bypassing standard process fdtable inspection.`
    );
  }
  if (!isTrusted && !sqPollActive && !fixedFilesActive) {
    severity = 'HIGH';
    reasons.push(
      `Process '${comm}' (PID ${pid}) holds an active anon_inode:[io_uring] ring outside the expected service baseline.`
    );
  }

  return {
    pid,
    comm,
    fd,
    sqThread,
    sqThreadCpu,
    sqHead,
    sqTail,
    cqHead,
    cqTail,
    userFiles,
    sqPollActive,
    fixedFilesActive,
    severity,
    reasons,
  };
}

/**
 * Compares the true Ring-0 `/proc/kcore` `prog_idr` XArray entries against userspace
 * `sys_bpf(BPF_PROG_GET_NEXT_ID)` IDs to detect self-hiding eBPF rootkits (`TripleCross`, `Boopkit`).
 */
export function diffKcoreProgIdrAgainstSysBpf(
  kcoreEntries: KcoreBpfProgEntry[],
  userspaceBpfIds: number[]
): HiddenEbpfDiffResult {
  const userSet = new Set(userspaceBpfIds);
  const kcoreIds = kcoreEntries.map((e) => e.id);
  const hiddenPrograms = kcoreEntries.filter((e) => !userSet.has(e.id));
  const hiddenIds = hiddenPrograms.map((p) => p.id);
  const compromised = hiddenIds.length > 0;

  return {
    kcoreIds,
    userspaceIds: [...userspaceBpfIds],
    hiddenIds,
    hiddenPrograms,
    compromised,
    severity: compromised ? 'CRITICAL' : 'CLEAN',
    summary: compromised
      ? `CRITICAL: Detected ${hiddenIds.length} hidden eBPF program(s) in /proc/kcore prog_idr [${hiddenIds.join(', ')}] missing from sys_bpf(BPF_PROG_GET_NEXT_ID)!`
      : `Clean: All ${kcoreIds.length} Ring-0 prog_idr entries match userspace sys_bpf().`,
  };
}

/**
 * Inspects eBPF xlated bytecode dumps and `/sys/kernel/tracing/enabled_functions`
 * for offensive helpers (`bpf_probe_write_user` #36, `bpf_override_return` #58) and
 * syscall-hiding trampolines (`__x64_sys_getdents64`, `__x64_sys_bpf`, `tcp4_seq_show`).
 */
export function analyzeBpfHelperAndTrampolineUsage(
  xlatedDump: string,
  enabledFunctionsText: string
): BpfBytecodeAuditFinding[] {
  const findings: BpfBytecodeAuditFinding[] = [];

  if (xlatedDump.includes('bpf_probe_write_user')) {
    findings.push({
      helperOrHook: 'bpf_probe_write_user (Helper #36)',
      severity: 'CRITICAL',
      description:
        'Loaded eBPF program invokes bpf_probe_write_user() to overwrite userspace buffers in-flight (classic TripleCross / Boopkit getdents64 & sys_bpf cloaking technique).',
      mitreTechnique: 'T1014 (Rootkit)',
    });
  }

  if (xlatedDump.includes('bpf_override_return')) {
    findings.push({
      helperOrHook: 'bpf_override_return (Helper #58)',
      severity: 'CRITICAL',
      description:
        'Loaded eBPF program invokes bpf_override_return() to hijack kernel function return values and bypass authentication or security checks.',
      mitreTechnique: 'T1547.006 (Kernel Modules and Extensions)',
    });
  }

  const sensitiveHooks = [
    { symbol: '__x64_sys_getdents64', desc: 'Directory & /proc PID listing hook (process/file cloaking)' },
    { symbol: '__x64_sys_bpf', desc: 'BPF syscall hook (bpftool / BPF_PROG_GET_NEXT_ID self-hiding)' },
    { symbol: 'tcp4_seq_show', desc: '/proc/net/tcp socket table hook (C2 port cloaking)' },
  ];

  for (const hook of sensitiveHooks) {
    if (
      enabledFunctionsText.includes(hook.symbol) &&
      (enabledFunctionsText.includes('bpf_trampoline') || enabledFunctionsText.includes('arch_ftrace_ops'))
    ) {
      findings.push({
        helperOrHook: `ftrace/bpf_trampoline -> ${hook.symbol}`,
        severity: 'HIGH',
        description: `Active kernel trampoline attached to ${hook.symbol}: ${hook.desc}.`,
        mitreTechnique: 'T1014 (Rootkit)',
      });
    }
  }

  return findings;
}

/**
 * Parses `perf script --fields comm,pid,brstacksym` hardware PMU Last Branch Record (LBR)
 * output for control-flow edges jumping into `bpf_trampoline_*` or `bpf_prog_*`.
 */
export function analyzePmuLbrBranchStack(perfScriptOutput: string): PmuLbrTrampolineHit[] {
  const hits: PmuLbrTrampolineHit[] = [];
  const lines = perfScriptOutput.split('\n');

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || (!line.includes('bpf_trampoline') && !line.includes('bpf_prog_'))) {
      continue;
    }

    const headMatch = line.match(/^(\S+)\s+(\d+)\s+(.*)$/);
    const comm = headMatch ? headMatch[1] : 'unknown';
    const pid = headMatch ? parseInt(headMatch[2], 10) : 0;
    const stackPart = headMatch ? headMatch[3] : line;

    const edges = stackPart.split(/\s+/);
    for (const edge of edges) {
      if (edge.includes('bpf_trampoline') || edge.includes('bpf_prog_')) {
        const [fromSym = 'kernel_text', toSym = edge] = edge.split('/');
        const isCritical =
          fromSym.includes('sys_bpf') ||
          fromSym.includes('sys_getdents') ||
          toSym.includes('bpf_trampoline');
        hits.push({
          comm,
          pid,
          fromSymbol: fromSym,
          toSymbol: toSym,
          severity: isCritical ? 'CRITICAL' : 'HIGH',
          description: `Silicon PMU LBR recorded Ring-0 branch ${fromSym} -> ${toSym} during ${comm} (PID ${pid}).`,
        });
      }
    }
  }

  return hits;
}

export function compileHostDefenseBundle(state?: Partial<DesiredState> | null) {
  const config = resolveHostDefenseConfig(state);
  const sysctlConf = compileKernelHardeningSysctl(state);
  const bpfLsmGuardC = compileBpfLsmGuardC(state);
  const drgnProgIdrScript = compileDrgnProgIdrAuditScript();
  const ioUringHuntScript = compileIoUringHuntScript();
  const ebpfRootkitHuntScript = compileEbpfRootkitHuntScript();
  const yaraRules = compileYaraGhostInTheRingRules();
  const rkhunterBundle = compileRkhunterConfig(state);

  return {
    config,
    scanners: HOST_MALWARE_SCANNERS,
    files: {
      '/etc/sysctl.d/99-axonwall-ghost-in-the-ring.conf': sysctlConf,
      '/etc/axonwall/bpf/ghost_in_the_ring_lsm.bpf.c': bpfLsmGuardC,
      '/usr/local/bin/audit_hidden_bpf_prog_idr.py': drgnProgIdrScript,
      '/usr/local/bin/hunt-io-uring-implants.sh': ioUringHuntScript,
      '/usr/local/bin/hunt-ebpf-rootkits.sh': ebpfRootkitHuntScript,
      '/etc/axonwall/yara/ghost_in_the_ring.yar': yaraRules,
      '/etc/rkhunter.conf.local': rkhunterBundle.rkhunterConfLocal,
      '/etc/cron.d/axonwall-host-defense': rkhunterBundle.cronScheduleFile,
      '/usr/local/bin/axonwall-hunt-rootkits': rkhunterBundle.unifiedRunnerScript,
    },
  };
}
