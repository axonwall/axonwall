#!/usr/bin/env bash
# =============================================================================
# Axonwall Ghost-in-the-Ring: Live io_uring Implant & SQPOLL Hunter
# Scans /proc/[pid]/fd and /proc/[pid]/fdinfo for anon_inode:[io_uring]
# =============================================================================
set -euo pipefail

echo "=== [1] Kernel io_uring Lockdown Sysctl Status ==="
sysctl kernel.io_uring_disabled kernel.io_uring_group 2>/dev/null || true

echo -e "\n=== [2] Scanning /proc for Active anon_inode:[io_uring] Rings ==="
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

echo -e "\n=== [3] Checking Kernel Threads for io-wq / iou-sqp Busy-Poll Workers ==="
ps -ef | grep -E "\[iou-sqp-|\[io-wq-" | grep -v grep || echo "[+] Clean: No io_uring SQPOLL kernel threads active."
