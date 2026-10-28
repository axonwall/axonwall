#!/usr/bin/env bash
# =============================================================================
# Axonwall Ghost-in-the-Ring: Live eBPF Rootkit & Hardware PMU LBR Triage
# =============================================================================
set -euo pipefail

echo "=== [1] Checking Kernel Taint & Offensive BPF Helper Warnings ==="
cat /proc/sys/kernel/tainted 2>/dev/null || true
dmesg 2>/dev/null | grep -iE "bpf_probe_write_user|bpf_override_return|taint" | tail -n 20 || echo "[+] No dmesg helper warnings."

echo -e "\n=== [2] Inspecting Ftrace / Trampoline Hooks on Critical Syscalls ==="
if [[ -r /sys/kernel/tracing/enabled_functions ]]; then
  grep -E "bpf_trampoline|__x64_sys_(getdents|bpf|read|kill|clone)|tcp4_seq_show" /sys/kernel/tracing/enabled_functions || echo "[+] No suspicious ftrace trampolines found."
else
  echo "[i] /sys/kernel/tracing/enabled_functions not readable or debugfs not mounted."
fi

echo -e "\n=== [3] Auditing Loaded eBPF Programs & XDP/TC Attachments ==="
if command -v bpftool >/dev/null 2>&1; then
  bpftool prog show || true
  bpftool net show || true

  echo -e "\n=== [4] Scanning eBPF Bytecode for Helper #36 (bpf_probe_write_user) & Helper #58 (bpf_override_return) ==="
  for id in $(bpftool prog show | awk -F: '/^[0-9]+:/ {print $1}'); do
    if bpftool prog dump xlated id "$id" 2>/dev/null | grep -qE "bpf_probe_write_user|bpf_override_return"; then
      echo "[!] CRITICAL: Program ID $id invokes offensive memory-patching helper!"
      bpftool prog show id "$id" || true
    fi
  done
else
  echo "[i] bpftool not installed."
fi

echo -e "\n=== [5] Sampling Silicon Hardware PMU Last Branch Records (Intel LBR / AMD BRS) ==="
if command -v perf >/dev/null 2>&1; then
  perf record -e branches:k -j any,k -a -o /tmp/axonwall-lbr.data -- sleep 1 >/dev/null 2>&1 && \
    perf script -i /tmp/axonwall-lbr.data --fields comm,pid,brstacksym 2>/dev/null | grep -E "bpf_trampoline|bpf_prog_" | head -n 20 || \
    echo "[+] No unexpected PMU LBR jumps into bpf_trampoline detected (or PMU LBR unsupported in VM)."
  rm -f /tmp/axonwall-lbr.data
else
  echo "[i] linux-perf not installed."
fi
