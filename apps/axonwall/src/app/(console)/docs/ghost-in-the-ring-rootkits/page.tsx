'use client';

import React from 'react';
import Link from 'next/link';
import { ShieldAlert, Cpu, Lock, Eye, Terminal, ArrowLeft } from 'lucide-react';

export default function GhostInTheRingDocsPage() {
  return (
    <div className="p-6 max-w-5xl mx-auto space-y-8 text-slate-200">
      <div className="flex items-center justify-between">
        <Link
          href="/security/rootkit-hunter"
          className="inline-flex items-center gap-2 text-xs font-semibold text-emerald-400 hover:text-emerald-300"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Rootkit &amp; Kernel Hunter Console
        </Link>
        <span className="text-xs font-mono text-slate-400">
          Author: Joshua Edward McLaughlin Cox • Ring-0 Telemetry Reference
        </span>
      </div>

      <header className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-3">
        <div className="flex items-center gap-2.5 text-emerald-400 text-xs font-mono uppercase tracking-wider">
          <ShieldAlert className="w-4 h-4" />
          <span>Axonwall Ring-0 Kernel Security Architecture</span>
        </div>
        <h1 className="text-2xl md:text-3xl font-bold text-white">
          Ghost in the Ring: Detecting io_uring &amp; eBPF Kernel Rootkits When kprobes and Syscall Tables Lie
        </h1>
        <p className="text-sm text-slate-400 leading-relaxed">
          How syscall-less <code className="text-amber-300">io_uring</code> implants (<strong>Curing</strong>,{' '}
          <strong>RingReaper</strong>) and self-hiding offensive eBPF rootkits (<strong>TripleCross</strong>,{' '}
          <strong>Boopkit</strong>, <strong>Symbiote</strong>) blind traditional Linux EDRs—and how Axonwall hunts them
          using <code className="text-cyan-300">/proc/kcore</code> <code className="text-cyan-300">prog_idr</code>{' '}
          XArray inspection, Silicon PMU Last Branch Records (<code className="text-purple-300">Intel LBR / AMD BRS</code>
          ), and preventive <code className="text-emerald-300">BPF_LSM</code> policies.
        </p>
      </header>

      {/* Section 1 */}
      <section className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 space-y-4">
        <h2 className="text-lg font-bold text-white flex items-center gap-2">
          <Cpu className="w-5 h-5 text-amber-400" />
          1. The Death of the Syscall Boundary: How io_uring Blinds EDRs
        </h2>
        <p className="text-xs text-slate-300 leading-relaxed">
          For twenty years, Linux host intrusion detection (`auditd`, Falco, Tetragon, Osquery) relied on a simple
          contract: if a userspace process wants to open a file, read `/etc/shadow`, spawn a socket, or transmit C2
          traffic, it must execute a `syscall` instruction (`openat`, `read`, `write`, `connect`, `sendmsg`).
        </p>
        <p className="text-xs text-slate-300 leading-relaxed">
          With <code>io_uring</code> (Linux 5.1+), a process calls <code>io_uring_setup(2)</code> and{' '}
          <code>mmap(2)</code>s two shared ring buffers between userspace and Ring-0: the{' '}
          <strong>Submission Queue (SQ)</strong> and <strong>Completion Queue (CQ)</strong>. When initialized with{' '}
          <code>IORING_SETUP_SQPOLL</code>, the kernel spawns a dedicated Ring-0 thread (<code>iou-sqp-&lt;pid&gt;</code>
          ) that busy-polls the Submission Queue in shared memory—performing file I/O, DNS resolution, and C2 socket
          reads/writes with <strong>zero system calls</strong>. Paired with <code>IOSQE_FIXED_FILE</code>, private file
          descriptors never even appear in the process&apos;s standard <code>files_struct</code> table.
        </p>
        <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-200 overflow-x-auto">{`  USERSPACE IMPLANT (e.g., Curing / RingReaper)
  +-------------------------------------------------------------------+
  |  1. Writes SQE (IORING_OP_OPENAT / IORING_OP_CONNECT / OP_SEND)   |
  |     directly into mmap()'d shared memory ring buffer.             |
  |  2. ZERO syscalls issued when IORING_SETUP_SQPOLL is active!      |
  +-------------------------------------------------------------------+
                                   |
        Shared Memory Ring         |  (Bypasses tracepoint/raw_syscalls/sys_enter!)
                                   v
  =====================================================================
  LINUX KERNEL (RING-0)
  +-------------------------------------------------------------------+
  |  [iou-sqp-<pid>] / [io-wq] Kernel Worker Thread                   |
  |    -> Polls SQ ring in kernel space                               |
  |    -> Dispatches io_openat2(), io_connect(), io_sendmsg()         |
  |    -> Writes result CQE to Completion Queue                       |
  +-------------------------------------------------------------------+`}</pre>
      </section>

      {/* Section 2 */}
      <section className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 space-y-4">
        <h2 className="text-lg font-bold text-white flex items-center gap-2">
          <Terminal className="w-5 h-5 text-cyan-400" />
          2. Hunting &amp; Locking Down io_uring Implants
        </h2>
        <p className="text-xs text-slate-300 leading-relaxed">
          Axonwall enforces <code>kernel.io_uring_disabled = 1</code> (restricting <code>io_uring_setup</code> to{' '}
          <code>kernel.io_uring_group = 994</code>) or <code>2</code> (disabled system-wide), and hooks{' '}
          <code>tracepoint:io_uring:io_uring_submit_req</code> directly inside <code>fs/io_uring.c</code>:
        </p>
        <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-emerald-300 overflow-x-auto">{`# Monitor io_uring SQE opcodes even when IORING_SETUP_SQPOLL is active:
# Opcode 18 = IORING_OP_OPENAT, 16 = IORING_OP_CONNECT, 26 = IORING_OP_SEND,
# Opcode 45 = IORING_OP_SOCKET, 46 = IORING_OP_URING_CMD
sudo bpftrace -e '
tracepoint:io_uring:io_uring_submit_req {
  if (args->opcode == 16 || args->opcode == 18 || args->opcode == 26 || args->opcode == 45 || args->opcode == 46) {
    printf("[IO_URING_ALERT] pid=%d comm=%s ring=%p opcode=%d flags=0x%x\\n",
           pid, comm, args->ctx, args->opcode, args->flags);
  }
}'`}</pre>
      </section>

      {/* Section 3 & 4 */}
      <section className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 space-y-4">
        <h2 className="text-lg font-bold text-white flex items-center gap-2">
          <Eye className="w-5 h-5 text-purple-400" />
          3. Detecting Self-Hiding eBPF Rootkits via /proc/kcore prog_idr &amp; Silicon PMU LBR
        </h2>
        <p className="text-xs text-slate-300 leading-relaxed">
          Offensive eBPF rootkits (<strong>TripleCross</strong>, <strong>Boopkit</strong>, <strong>Symbiote</strong>)
          abuse <code>bpf_probe_write_user()</code> (Helper <code>#36</code>) and <code>bpf_override_return()</code>{' '}
          (Helper <code>#58</code>) on <code>sys_exit_getdents64</code> and <code>fexit/__x64_sys_bpf</code> to hide
          their PIDs, files, and even their own eBPF program IDs from <code>bpftool prog show</code>.
        </p>
        <p className="text-xs text-slate-300 leading-relaxed">
          Because the kernel must maintain every loaded <code>struct bpf_prog</code> inside the internal{' '}
          <code>prog_idr</code> radix tree / XArray so the scheduler and XDP drivers can invoke it, Axonwall walks{' '}
          <code>prog_idr</code> directly in <code>/proc/kcore</code> via <code>drgn</code> and diffs the true Ring-0 IDs
          against <code>sys_bpf(BPF_PROG_GET_NEXT_ID)</code>. In parallel, Silicon PMU{' '}
          <strong>Last Branch Records (Intel LBR / AMD BRS)</strong> record every hardware jump into{' '}
          <code>bpf_trampoline_*</code> and <code>bpf_prog_*</code> JIT pages inside CPU MSRs that eBPF cannot falsify.
        </p>
      </section>

      {/* Section 5 */}
      <section className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 space-y-4">
        <h2 className="text-lg font-bold text-white flex items-center gap-2">
          <Lock className="w-5 h-5 text-emerald-400" />
          4. Preventive Ring-0 Architecture: BPF_LSM + Kernel Lockdown Confidentiality
        </h2>
        <p className="text-xs text-slate-300 leading-relaxed">
          Axonwall compiles and enforces a preventive <code>BPF_LSM</code> policy (<code>SEC(&quot;lsm/bpf&quot;)</code>{' '}
          and <code>SEC(&quot;lsm/uring_sqpoll&quot;)</code>) paired with{' '}
          <code>lockdown=confidentiality</code> (which blocks <code>bpf_probe_write_user</code> and{' '}
          <code>bpf_override_return</code> at the kernel verifier level) so that even a compromise of <code>root</code>{' '}
          cannot load an unauthorized eBPF program or spawn a zero-syscall <code>io_uring</code> SQPOLL worker.
        </p>
      </section>
    </div>
  );
}
