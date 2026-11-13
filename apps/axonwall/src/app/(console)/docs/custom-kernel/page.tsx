import React from 'react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';
import {
  Cpu,
  ShieldCheck,
  Layers,
  Terminal,
  HardDrive,
  Network,
  Activity,
  RotateCcw,
  Lock,
} from 'lucide-react';

export const metadata = {
  title: 'Custom Hardened Kernels (Universal & Hardware-Stripped) | Axonwall Documentation',
  description:
    'Architecture, KSPP hardening matrix, Kubernetes/OpenZFS/nftables/eBPF compatibility, hardware detection, and safe rollback workflows for Axonwall Linux 6.12 LTS kernels.',
};

export default function CustomKernelDocPage() {
  return (
    <div className="space-y-12">
      {/* Header */}
      <div className="space-y-4 border-b border-slate-800 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-950/60 border border-indigo-500/30 text-indigo-300 text-xs font-semibold">
          <ShieldCheck className="w-3.5 h-3.5" /> Linux 6.12 LTS • KSPP Hardened • Universal &amp; Hardware-Locked
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Custom Hardened Kernels &amp; Hardware Studio
        </h1>
        <p className="text-base text-slate-400 leading-relaxed max-w-3xl">
          Axonwall ships a reproducible Linux 6.12 LTS kernel pipeline designed specifically for headless{' '}
          <strong className="text-white">k3s / containerd</strong>, <strong className="text-white">OpenZFS + OpenEBS</strong> storage,{' '}
          <strong className="text-white">nftables</strong> NGFW packet processing, and <strong className="text-white">eBPF CO-RE</strong>{' '}
          observability—paired with an interactive{' '}
          <strong className="text-indigo-300">Custom Kernel Studio</strong> (<code className="font-mono text-slate-200">/system/kernel</code>)
          that detects host hardware and compiles minimal <code className="font-mono text-slate-200">localmodconfig</code> kernels.
        </p>
      </div>

      {/* 1. Architecture & Container-OS Comparison */}
      <section id="architecture" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Layers className="w-6 h-6 text-indigo-400" /> 1. Hardened Container &amp; Storage Kernel Comparison
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          General-purpose desktop hardening patches (such as <code className="font-mono text-slate-200">linux-hardened</code>) frequently
          break cloud-native workloads by disabling unprivileged user namespaces, blocking eBPF{' '}
          <code className="font-mono text-slate-200">bpf_probe_read_kernel</code>, or stripping kernel symbols required by out-of-tree
          OpenZFS DKMS modules. Axonwall synthesizes proven server and container-OS patterns instead:
        </p>

        <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/60">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-900/90 text-slate-400 uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Reference Kernel</th>
                <th className="py-3 px-4">Strength Adopted by Axonwall</th>
                <th className="py-3 px-4">Compatibility Trade-off</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              <tr>
                <td className="py-3 px-4 font-semibold text-white">Talos Linux</td>
                <td className="py-3 px-4">KSPP memory/slab/stack hardening, module signing, stripped unused drivers &amp; legacy protocols.</td>
                <td className="py-3 px-4">No local shell/DKMS; Axonwall retains module signing in integrity mode + ZFS symbol support.</td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-semibold text-white">Fedora CoreOS / Flatcar</td>
                <td className="py-3 px-4">Upstream LTS paired with cgroups v2, SELinux/LSM enforcement, overlayfs &amp; wireguard out of the box.</td>
                <td className="py-3 px-4">Full distro footprint; Axonwall trims desktop media/sound/wireless bloat.</td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-semibold text-white">Alpine <code className="font-mono">linux-virt</code></td>
                <td className="py-3 px-4">Ultra-small surface for virtualized &amp; bare-metal headless hosts.</td>
                <td className="py-3 px-4">Misses broad enterprise RAID/HBA/25GbE NIC drivers; Axonwall offers both Universal &amp; Stripped tiers.</td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-semibold text-white">Debian 13 LTS + LSM</td>
                <td className="py-3 px-4">Broad server/cloud driver compatibility and clean <code className="font-mono">.deb</code> / ZFSBootMenu packaging.</td>
                <td className="py-3 px-4">Desktop subsystems enabled by default; Axonwall strips them while layering KSPP &amp; BPF-LSM.</td>
              </tr>
              <tr className="bg-rose-950/20">
                <td className="py-3 px-4 font-semibold text-rose-300">Desktop <code className="font-mono">linux-hardened</code></td>
                <td className="py-3 px-4">Strict heap/JIT/namespace restrictions for single-user workstations.</td>
                <td className="py-3 px-4 text-rose-200">
                  Breaks rootless <code className="font-mono">userns</code>, eBPF tracers, <code className="font-mono">overlayfs</code>, and OpenZFS DKMS.
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <Callout type="warning" title="Why Axonwall Avoids Lockdown Confidentiality Mode">
          Axonwall enables <code className="font-mono">CONFIG_SECURITY_LOCKDOWN_LSM=y</code> with{' '}
          <code className="font-mono">CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY=y</code> instead of{' '}
          <code className="font-mono">confidentiality</code>. Integrity mode protects <code className="font-mono">/dev/mem</code>,{' '}
          <code className="font-mono">kexec</code>, and unsigned kernel module loads while preserving <code className="font-mono">DEBUG_INFO_BTF</code>,{' '}
          <code className="font-mono">fprobe</code>, and eBPF CO-RE telemetry needed by Cilium/Tetragon/Axonwall eBPF agents.
        </Callout>
      </section>

      {/* 2. Best Practices Kconfig Matrix */}
      <section id="kconfig-matrix" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Lock className="w-6 h-6 text-emerald-400" /> 2. Axonwall Kernel Best Practices Matrix
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-semibold text-emerald-400 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4" /> KSPP &amp; Lockdown
            </div>
            <ul className="space-y-1 text-slate-300 list-disc pl-4">
              <li><code className="font-mono text-slate-200">CONFIG_SECURITY_LOCKDOWN_LSM=y</code> (<code className="font-mono">integrity</code>)</li>
              <li><code className="font-mono text-slate-200">CONFIG_BPF_LSM=y</code> &amp; <code className="font-mono">CONFIG_SECURITY_SELINUX=y</code></li>
              <li><code className="font-mono text-slate-200">INIT_ON_ALLOC_DEFAULT_ON</code>, <code className="font-mono">ZERO_CALL_USED_REGS</code>, <code className="font-mono">SLAB_FREELIST_HARDENED</code></li>
              <li><code className="font-mono text-slate-200">CONFIG_MODULE_SIG=y</code> (<code className="font-mono">sha512</code>)</li>
              <li>Disables <code className="font-mono">KEXEC</code>, <code className="font-mono">HIBERNATION</code>, <code className="font-mono">DEVMEM</code>, <code className="font-mono">DCCP</code>, <code className="font-mono">RDS</code>, <code className="font-mono">TIPC</code></li>
            </ul>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-semibold text-sky-400 flex items-center gap-2">
              <Cpu className="w-4 h-4" /> Kubernetes (<code className="font-mono">k3s</code> / <code className="font-mono">containerd</code>)
            </div>
            <ul className="space-y-1 text-slate-300 list-disc pl-4">
              <li><code className="font-mono text-slate-200">CONFIG_USER_NS=y</code> + sysctl <code className="font-mono">kernel.unprivileged_userns_clone=1</code></li>
              <li>cgroups v2 (<code className="font-mono">CGROUPS</code>, <code className="font-mono">CGROUP_BPF</code>, <code className="font-mono">MEMCG</code>, <code className="font-mono">BLK_CGROUP</code>)</li>
              <li><code className="font-mono text-slate-200">CONFIG_SECCOMP_FILTER=y</code> &amp; <code className="font-mono">CONFIG_OVERLAY_FS=m</code></li>
              <li><code className="font-mono text-slate-200">VETH</code>, <code className="font-mono">BRIDGE</code>, <code className="font-mono">VXLAN</code>, <code className="font-mono">GENEVE</code>, <code className="font-mono">IP_VS</code></li>
              <li>Full CNI netfilter / <code className="font-mono">xtables</code> match &amp; masquerade hooks</li>
            </ul>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-semibold text-amber-400 flex items-center gap-2">
              <HardDrive className="w-4 h-4" /> Storage (OpenZFS &amp; OpenEBS)
            </div>
            <ul className="space-y-1 text-slate-300 list-disc pl-4">
              <li><code className="font-mono text-slate-200"># CONFIG_TRIM_UNUSED_KSYMS is not set</code> + <code className="font-mono">CONFIG_KALLSYMS=y</code> (required for ZFS DKMS)</li>
              <li><code className="font-mono text-slate-200">NVME_CORE</code> / <code className="font-mono">BLK_DEV_NVME</code> &amp; NVMe-oF TCP multipath</li>
              <li><code className="font-mono text-slate-200">DM_CRYPT</code>, <code className="font-mono">DM_THIN_PROVISIONING</code>, <code className="font-mono">MD</code> RAID</li>
              <li><code className="font-mono text-slate-200">EXT4_FS</code>, <code className="font-mono">XFS_FS</code>, <code className="font-mono">ISCSI_TCP</code>, <code className="font-mono">NFSD</code></li>
            </ul>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-semibold text-purple-400 flex items-center gap-2">
              <Network className="w-4 h-4" /> <code className="font-mono">nftables</code> NGFW &amp; eBPF Observability
            </div>
            <ul className="space-y-1 text-slate-300 list-disc pl-4">
              <li><code className="font-mono text-slate-200">NF_TABLES</code> (<code className="font-mono">INET</code>, <code className="font-mono">NETDEV</code>, <code className="font-mono">FLOW_OFFLOAD</code>, <code className="font-mono">SYNPROXY</code>, <code className="font-mono">QUOTA</code>)</li>
              <li><code className="font-mono text-slate-200">WIREGUARD</code>, <code className="font-mono">XFRM_USER</code>/<code className="font-mono">INET_ESP</code>, <code className="font-mono">CAKE</code>, <code className="font-mono">FQ_CODEL</code>, <code className="font-mono">BBR</code></li>
              <li><code className="font-mono text-slate-200">BPF_SYSCALL=y</code>, <code className="font-mono">BPF_JIT_ALWAYS_ON=y</code>, <code className="font-mono">BPF_UNPRIV_DEFAULT_OFF=y</code></li>
              <li><code className="font-mono text-slate-200">DEBUG_INFO_BTF=y</code>, <code className="font-mono">DEBUG_INFO_BTF_MODULES=y</code>, <code className="font-mono">XDP_SOCKETS=y</code>, <code className="font-mono">FPROBE=y</code></li>
            </ul>
          </div>
        </div>
      </section>

      {/* 3. Two Delivery Tiers */}
      <section id="tiers" className="space-y-4">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Activity className="w-6 h-6 text-indigo-400" /> 3. Two Delivery Tiers: Universal vs. Hardware-Stripped
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
          <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white">Tier 1 — Axonwall Universal Hardened Kernel</h3>
            <p className="text-slate-400 text-xs leading-relaxed">
              Combines <code className="font-mono text-slate-200">00-universal-hardware-base.config</code> (Debian-13-equivalent
              bare-metal server, NVMe, HBA, 1GbE–100GbE NIC, and cloud/hypervisor drivers) with fragments{' '}
              <code className="font-mono text-slate-200">01..06</code>. Ships cleanly across diverse appliances while stripping
              sound, GPU/DRM, Bluetooth, and Wi-Fi bloat.
            </p>
          </div>
          <div className="p-5 rounded-xl bg-slate-900/80 border border-indigo-500/30 space-y-2">
            <h3 className="font-bold text-indigo-300">Tier 2 — Hardware-Locked Stripped Kernel (<code className="font-mono">localmodconfig</code>)</h3>
            <p className="text-slate-400 text-xs leading-relaxed">
              Uses <strong className="text-white">System → Custom Kernel Studio</strong> (<code className="font-mono">/system/kernel</code>)
              to inventory live host CPU ISA (<code className="font-mono">x86-64-v2</code> / <code className="font-mono">v3</code> /{' '}
              <code className="font-mono">v4</code> / <code className="font-mono">native</code>), IOMMU, UEFI Secure Boot, TPM2,
              hardware watchdogs, PCIe NICs/HBAs/NVMe, and active <code className="font-mono">lsmod</code> modules, then runs{' '}
              <code className="font-mono">localmodconfig</code> while pinning essential k3s, ZFS, nftables, and eBPF symbols.
            </p>
          </div>
        </div>
      </section>

      {/* 4. CLI & Build Reference */}
      <section id="cli" className="space-y-4">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Terminal className="w-6 h-6 text-emerald-400" /> 4. CLI &amp; Offline Build Reference
        </h2>
        <CodeBlock
          title="Inspect hardware, audit the running kernel, and synthesize a stripped Kconfig"
          language="bash"
          code={`# Inventory CPU flags, IOMMU, TPM2, PCIe devices, NICs, NVMe, and loaded modules
axonwallctl kernel detect

# Run the 24-check Axonwall KSPP + k3s + ZFS + nftables + eBPF posture audit
axonwallctl kernel audit

# Generate a hardware-locked localmodconfig bundle + hardened sysctl drop-in
axonwallctl kernel config --mode stripped --output-dir ./out-kernel`}
        />
        <CodeBlock
          title="Build universal or hardware-stripped .deb kernel packages via packaging/kernel/build-kernel.sh"
          language="bash"
          code={`# Universal hardened Debian-equivalent kernel .deb build
./packaging/kernel/build-kernel.sh --mode universal --output-dir ./out-universal

# Hardware-stripped build with captured lsmod and x86-64-v3 ISA tuning
lsmod > /tmp/host-lsmod.txt
./packaging/kernel/build-kernel.sh \\
  --mode stripped \\
  --lsmod /tmp/host-lsmod.txt \\
  --march x86-64-v3 \\
  --lockdown integrity \\
  --output-dir ./out-stripped`}
        />
      </section>

      {/* 5. Safe Rollback & Staging */}
      <section id="rollback" className="space-y-4">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <RotateCcw className="w-6 h-6 text-amber-400" /> 5. Safe Rollback &amp; Boot Staging
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Installing a stripped kernel never removes your currently running fallback kernel in place:
        </p>
        <ul className="space-y-2 text-xs text-slate-300 list-disc pl-5">
          <li>
            <strong className="text-white">ZFS Boot Menu (<code className="font-mono">zbm</code> mode):</strong>{' '}
            <code className="font-mono">axonwalld</code> snapshots the active root dataset, clones a new Boot Environment, installs
            the built <code className="font-mono">linux-image-*</code> and <code className="font-mono">linux-headers-*</code>{' '}
            <code className="font-mono">.deb</code> packages inside the staged BE, and arms one-shot boot verification. If the
            new kernel fails to report healthy, ZFSBootMenu or the hardware watchdog falls back to the prior BE automatically.
          </li>
          <li>
            <strong className="text-white">Standard A/B &amp; Rolling Installs (<code className="font-mono">ab</code> / <code className="font-mono">rolling</code>):</strong>{' '}
            <code className="font-mono">dpkg -i</code> installs the new kernel side-by-side with{' '}
            <code className="font-mono">update-grub</code> preserving the previous working kernel entry and{' '}
            <code className="font-mono">grub-reboot</code> one-time trial boot support.
          </li>
        </ul>
      </section>
    </div>
  );
}
