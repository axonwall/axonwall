import React from 'react';
import Link from 'next/link';
import { ShieldAlert, Cpu, Lock, Eye, Terminal, Activity, FileCheck2, Bug } from 'lucide-react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'Host Malware, rkhunter & Ghost-in-the-Ring Kernel Rootkit Hunter | Axonwall Documentation',
  description:
    'Detecting and preventing user-space malware and Ring-0 io_uring & eBPF kernel rootkits using rkhunter, chkrootkit, ClamAV, AIDE, YARA, Lynis, BPF_LSM, /proc/kcore prog_idr inspection, and Silicon PMU Last Branch Records (LBR).',
};

export default function GhostInTheRingDocsPage() {
  return (
    <div className="space-y-12">
      {/* Page Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Ring-0 Kernel Telemetry &amp; Host Malware Defense Suite
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          Host Malware &amp; Ghost-in-the-Ring Kernel Rootkit Hunter
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Axonwall pairs six battle-tested host integrity &amp; malware engines (<code className="text-white font-mono">rkhunter</code>,{' '}
          <code className="text-white font-mono">chkrootkit</code>, <code className="text-white font-mono">ClamAV</code>,{' '}
          <code className="text-white font-mono">AIDE</code>, <code className="text-white font-mono">YARA</code>, and{' '}
          <code className="text-white font-mono">Lynis</code>) with our <strong>Ghost-in-the-Ring</strong> Ring-0 telemetry
          engine—engineered to catch syscall-less <code className="text-amber-300 font-mono">io_uring</code> implants and
          self-hiding <code className="text-cyan-300 font-mono">eBPF</code> rootkits when kprobes and syscall tables lie.
        </p>
      </div>

      {/* Multi-Engine Host Malware & Integrity Suite */}
      <section id="host-scanners" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Bug className="w-6 h-6 text-emerald-400" /> 1. Six-Engine Host Malware &amp; Integrity Suite (<code className="font-mono text-emerald-400">host-malware-rootkit</code>)
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Network perimeter defense is incomplete if the appliance or hypervisor host itself is compromised. Axonwall
          orchestrates six complementary host security scanners from a unified declarative configuration (
          <code className="text-emerald-400 font-mono">/etc/axonwall/rootkit.yaml</code>):
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">rkhunter &amp; chkrootkit</h3>
            <p className="text-slate-400 leading-relaxed">
              Scans kernel symbol tables (<code className="text-slate-200">/proc/kallsyms</code>), LKM module paths,
              hidden <code className="text-slate-200">/proc</code> PIDs, promiscuous raw sockets, and trojaned system
              binaries (<code className="text-slate-200">ps</code>, <code className="text-slate-200">ss</code>,{' '}
              <code className="text-slate-200">ls</code>, <code className="text-slate-200">sshd</code>).
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">ClamAV Real-Time &amp; Scheduled</h3>
            <p className="text-slate-400 leading-relaxed">
              Combines <code className="text-slate-200">freshclam</code> signature updates with{' '}
              <code className="text-slate-200">clamonacc</code> Linux <code className="text-slate-200">fanotify</code>{' '}
              on-access scanning across <code className="text-slate-200">/tmp</code>, <code className="text-slate-200">/var/tmp</code>,{' '}
              <code className="text-slate-200">/dev/shm</code>, and ZFS NAS share mountpoints.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">AIDE Cryptographic FIM</h3>
            <p className="text-slate-400 leading-relaxed">
              Verifies SHA-512 + xattr + inode cryptographic baselines across <code className="text-slate-200">/boot</code>,{' '}
              <code className="text-slate-200">/etc/axonwall</code>, <code className="text-slate-200">/usr/bin</code>, and{' '}
              <code className="text-slate-200">/usr/sbin</code> to detect unauthorized binary tampering.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">YARA Live Process &amp; ELF Hunting</h3>
            <p className="text-slate-400 leading-relaxed">
              Sweeps live process memory maps (<code className="text-slate-200">/proc/&lt;pid&gt;/mem</code>), anonymous{' '}
              <code className="text-slate-200">memfd_create</code> fileless payloads, and eBPF ELF sections against
              curated APT &amp; rootkit rule packs.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">Lynis CIS &amp; Kernel Hardening Audit</h3>
            <p className="text-slate-400 leading-relaxed">
              Continuously scores the appliance against CIS / NIST kernel sysctl, PAM, SSH, and systemd sandboxing
              benchmarks and exports a real-time Hardening Index to the Web Console.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-emerald-500/30 space-y-2">
            <h3 className="font-bold text-emerald-400 text-sm">Automated Quarantine &amp; Alerting</h3>
            <p className="text-slate-400 leading-relaxed">
              Optional automatic quarantine of malicious ELF drops into{' '}
              <code className="text-slate-200">/var/lib/axonwall/quarantine</code> (mode <code className="text-slate-200">0000</code>),
              instant VictoriaLogs emission, and AI Security Copilot root-cause triage.
            </p>
          </div>
        </div>
      </section>

      {/* Section 2: Death of the Syscall Boundary */}
      <section id="io-uring" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Cpu className="w-6 h-6 text-amber-400" />
          2. The Death of the Syscall Boundary: How io_uring Blinds Traditional EDRs
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          For twenty years, Linux host intrusion detection (<code className="text-white font-mono">auditd</code>, Falco,
          Tetragon, Osquery) relied on a simple contract: if a userspace process wants to open a file, read{' '}
          <code className="text-white font-mono">/etc/shadow</code>, spawn a socket, or transmit C2 traffic, it must
          execute a <code className="text-emerald-400 font-mono">syscall</code> instruction (
          <code className="text-white font-mono">openat</code>, <code className="text-white font-mono">read</code>,{' '}
          <code className="text-white font-mono">write</code>, <code className="text-white font-mono">connect</code>,{' '}
          <code className="text-white font-mono">sendmsg</code>).
        </p>
        <p className="text-sm text-slate-300 leading-relaxed">
          With <code className="text-amber-300 font-mono">io_uring</code> (Linux 5.1+), a process calls{' '}
          <code className="text-white font-mono">io_uring_setup(2)</code> and <code className="text-white font-mono">mmap(2)</code>s
          two shared ring buffers between userspace and Ring-0: the <strong>Submission Queue (SQ)</strong> and{' '}
          <strong>Completion Queue (CQ)</strong>. When initialized with{' '}
          <code className="text-amber-300 font-mono">IORING_SETUP_SQPOLL</code>, the kernel spawns a dedicated Ring-0
          thread (<code className="text-white font-mono">iou-sqp-&lt;pid&gt;</code>) that busy-polls the Submission Queue
          in shared memory—performing file I/O, DNS resolution, and C2 socket reads/writes with{' '}
          <strong>zero system calls</strong>. Paired with <code className="text-amber-300 font-mono">IOSQE_FIXED_FILE</code>,
          private file descriptors never even appear in the process&apos;s standard <code className="text-white font-mono">files_struct</code>{' '}
          table.
        </p>

        <CodeBlock
          title="How Curing / RingReaper Implants Bypass Syscall-Based EDRs"
          language="text"
          code={`  USERSPACE IMPLANT (e.g., Curing / RingReaper)
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
  +-------------------------------------------------------------------+`}
        />
      </section>

      {/* Section 3: Hunting & Locking Down io_uring */}
      <section id="uring-lockdown" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Terminal className="w-6 h-6 text-cyan-400" />
          3. Hunting &amp; Locking Down io_uring Implants
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Axonwall enforces <code className="text-emerald-400 font-mono">kernel.io_uring_disabled = 2</code> (or{' '}
          <code className="text-emerald-400 font-mono">1</code> restricting <code className="text-white font-mono">io_uring_setup</code>{' '}
          to a dedicated GID), audits <code className="text-white font-mono">anon_inode:[io_uring]</code> descriptors and{' '}
          <code className="text-white font-mono">iou-sqp-*</code> kernel threads, and hooks{' '}
          <code className="text-cyan-300 font-mono">tracepoint:io_uring:io_uring_submit_req</code> directly inside{' '}
          <code className="text-white font-mono">fs/io_uring.c</code>:
        </p>

        <CodeBlock
          title="Ring-0 io_uring Opcode Inspection"
          language="bash"
          code={`# Monitor io_uring SQE opcodes even when IORING_SETUP_SQPOLL is active:
# Opcode 18 = IORING_OP_OPENAT, 16 = IORING_OP_CONNECT, 26 = IORING_OP_SEND,
# Opcode 45 = IORING_OP_SOCKET, 46 = IORING_OP_URING_CMD
sudo bpftrace -e '
tracepoint:io_uring:io_uring_submit_req {
  if (args->opcode == 16 || args->opcode == 18 || args->opcode == 26 || args->opcode == 45 || args->opcode == 46) {
    printf("[IO_URING_ALERT] pid=%d comm=%s ring=%p opcode=%d flags=0x%x\\n",
           pid, comm, args->ctx, args->opcode, args->flags);
  }
}'`}
        />
      </section>

      {/* Section 4: eBPF Rootkits & PMU LBR */}
      <section id="ebpf-pmu" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Eye className="w-6 h-6 text-purple-400" />
          4. Detecting Self-Hiding eBPF Rootkits via /proc/kcore prog_idr &amp; Silicon PMU LBR
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Offensive eBPF rootkits (<strong>TripleCross</strong>, <strong>Boopkit</strong>, <strong>Symbiote</strong>)
          abuse <code className="text-rose-400 font-mono">bpf_probe_write_user()</code> (Helper <code className="font-mono">#36</code>)
          and <code className="text-rose-400 font-mono">bpf_override_return()</code> (Helper <code className="font-mono">#58</code>)
          on <code className="text-white font-mono">sys_exit_getdents64</code> and{' '}
          <code className="text-white font-mono">fexit/__x64_sys_bpf</code> to hide their PIDs, files, and even their own
          eBPF program IDs from <code className="text-white font-mono">bpftool prog show</code>.
        </p>
        <p className="text-sm text-slate-300 leading-relaxed">
          Because the kernel must maintain every loaded <code className="text-cyan-300 font-mono">struct bpf_prog</code>{' '}
          inside the internal <code className="text-cyan-300 font-mono">prog_idr</code> radix tree / XArray so the
          scheduler and XDP drivers can invoke it, Axonwall walks <code className="text-cyan-300 font-mono">prog_idr</code>{' '}
          directly in <code className="text-white font-mono">/proc/kcore</code> and diffs the true Ring-0 IDs against{' '}
          <code className="text-white font-mono">sys_bpf(BPF_PROG_GET_NEXT_ID)</code>. In parallel, Silicon PMU{' '}
          <strong>Last Branch Records (Intel LBR / AMD BRS)</strong> and <code className="text-purple-300 font-mono">perf_event_open</code>{' '}
          counters (<code className="text-purple-300 font-mono">instructions:k</code>,{' '}
          <code className="text-purple-300 font-mono">cycles:k</code>) record every hardware jump into{' '}
          <code className="text-white font-mono">bpf_trampoline_*</code> and <code className="text-white font-mono">bpf_prog_*</code>{' '}
          JIT pages inside CPU Model-Specific Registers (MSRs) that eBPF cannot falsify.
        </p>
      </section>

      {/* Section 5: Preventive BPF_LSM + Configuration */}
      <section id="lsm-bpf" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Lock className="w-6 h-6 text-emerald-400" />
          5. Preventive Ring-0 Architecture: BPF_LSM &amp; Declarative Configuration
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Axonwall compiles and enforces a preventive <code className="text-emerald-400 font-mono">BPF_LSM</code> policy (
          <code className="text-white font-mono">SEC(&quot;lsm/bpf&quot;)</code>,{' '}
          <code className="text-white font-mono">SEC(&quot;lsm/uring_sqpoll&quot;)</code>, and{' '}
          <code className="text-white font-mono">SEC(&quot;lsm/uring_cmd&quot;)</code>) paired with{' '}
          <code className="text-emerald-400 font-mono">kernel.unprivileged_bpf_disabled = 1</code> and{' '}
          <code className="text-emerald-400 font-mono">lockdown=confidentiality</code> so that even a compromise of{' '}
          <code className="text-white font-mono">root</code> cannot load an unauthorized eBPF program or spawn a
          zero-syscall <code className="text-white font-mono">io_uring</code> worker.
        </p>

        <CodeBlock
          title="/etc/axonwall/rootkit.yaml (Declarative Host & Ring-0 Hunter Config)"
          language="yaml"
          code={`enabled: true
scanScheduleCron: "0 */6 * * *"
autoQuarantine: false
quarantineDir: "/var/lib/axonwall/quarantine"

scanners:
  rkhunter: true
  chkrootkit: true
  clamav: true
  clamavRealtime: true
  aide: true
  yara: true
  lynis: true

ghostInTheRing:
  enabled: true
  lsmBpfLockdown: true
  blockUnpinnedBpfPrograms: true
  restrictIoUring: "disabled"       # "allow" | "restricted" | "disabled"
  bpftoolAuditIntervalSec: 60
  pmuTelemetryEnabled: true
  pmuSampleFrequencyHz: 99
  pmuAnomalyThresholdPct: 18
  alertOnHelperCalls:
    - bpf_probe_write_user
    - bpf_override_return
    - bpf_send_signal`}
        />

        <Callout type="tip" title="Manage via Web Console, Neovim TUI, or CLI">
          Configure and trigger deep Ring-0 + Malware scans from the Web Console at{' '}
          <Link href="/security/rootkit-hunter" className="font-mono text-emerald-300 underline">
            /security/rootkit-hunter
          </Link>
          , in the Neovim Super Configurator via <code className="font-mono text-emerald-300">axonwall-config rootkit</code>,
          or from the shell with <code className="font-mono text-emerald-300">axonwallctl rootkit-scan</code>.
        </Callout>
      </section>
    </div>
  );
}
