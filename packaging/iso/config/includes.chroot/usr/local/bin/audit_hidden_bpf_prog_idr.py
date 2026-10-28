#!/usr/bin/env drgn
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

userspace_ids = set()
try:
    out = subprocess.check_output(["bpftool", "-j", "prog", "show"], stderr=subprocess.DEVNULL)
    for p in json.loads(out.decode("utf-8")):
        if "id" in p:
            userspace_ids.add(int(p["id"]))
except Exception:
    pass

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
    print(f"\n[!] ALERT: Detected {len(hidden)} hidden eBPF program(s) in prog_idr: {hidden}")
else:
    print(f"\n[+] OK: All {len(kcore_ids)} Ring-0 prog_idr entries match userspace sys_bpf().")
