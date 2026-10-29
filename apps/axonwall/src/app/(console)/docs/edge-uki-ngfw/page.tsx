import React from 'react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';
import {
  Cpu,
  Shield,
  Zap,
  Globe,
  ArrowRightLeft,
  Server,
  Terminal,
  Lock,
  CheckCircle2,
  Layers,
} from 'lucide-react';

export const metadata = {
  title: 'Super-Slim Edge NGFW (Single-File UEFI UKI & Pure-Go PID 1) | Axonwall Documentation',
  description:
    'Technical documentation for the Axonwall Super-Slim Edge NGFW: a zero-surface, stateless UEFI Unified Kernel Image (UKI) running axonwall-satellite as pure-Go PID 1 with CONFIG_MODULES=n, pure-Go Cloud-Init, Dual-Stack IPv6, and Active-Standby Edge HA.',
};

export default function EdgeUkiNgfwDocPage() {
  return (
    <div className="space-y-12">
      {/* Header */}
      <div className="space-y-4 border-b border-slate-800 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <Cpu className="w-3.5 h-3.5" /> Zero-Surface Perimeter • Single-File UEFI UKI
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Super-Slim Edge NGFW (Single-File UEFI UKI)
        </h1>
        <p className="text-base text-slate-400 leading-relaxed max-w-3xl">
          The Axonwall Super-Slim Edge NGFW (<code className="text-emerald-400 font-mono">axonwall-edge</code>) is a
          stateless, memory-only perimeter firewall engineered to sit directly on untrusted WAN links—either as a
          dedicated bare-metal/virtual appliance or as an isolated Hosted Edge VM orchestrated by an internal Axonwall
          host. By compiling a hardware-specific monolithic Linux 6.12 LTS kernel (<code className="text-slate-200 font-mono">CONFIG_MODULES=n</code>)
          with <code className="text-slate-200 font-mono">axonwall-satellite</code> embedded as a static pure-Go{' '}
          <strong className="text-white">PID 1 (<code className="font-mono">/init</code>)</strong>, it eliminates every
          userland shell, package manager, and loadable kernel module.
        </p>
      </div>

      {/* 1. Zero-Surface Architecture */}
      <section id="architecture" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Shield className="w-6 h-6 text-emerald-400" /> 1. Zero-Surface Monolithic Architecture
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Traditional firewall distributions ship hundreds of userland binaries (<code className="text-slate-200 font-mono">/bin/sh</code>,{' '}
          <code className="text-slate-200 font-mono">bash</code>, <code className="text-slate-200 font-mono">python</code>,{' '}
          <code className="text-slate-200 font-mono">curl</code>, <code className="text-slate-200 font-mono">sshd</code>,{' '}
          <code className="text-slate-200 font-mono">libc.so</code>) and thousands of loadable kernel modules (<code className="text-slate-200 font-mono">.ko</code>).
          If an attacker compromises a perimeter service, they immediately leverage those binaries for Living-off-the-Land
          (LotL) execution or load a kernel rootkit.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-emerald-400 text-sm flex items-center gap-2">
              <Lock className="w-4 h-4" /> Zero Shell &amp; Zero LotL Surface
            </div>
            <p className="text-slate-400 leading-relaxed">
              The initramfs contains <strong className="text-slate-200">only</strong> the static Go binary at{' '}
              <code className="text-slate-200 font-mono">/init</code> (compiled with <code className="text-slate-200 font-mono">CGO_ENABLED=0</code>)
              and TLS CA roots. No <code className="text-slate-200 font-mono">/bin/sh</code>,{' '}
              <code className="text-slate-200 font-mono">busybox</code>, <code className="text-slate-200 font-mono">nft</code> CLI,{' '}
              <code className="text-slate-200 font-mono">ip</code> CLI, or shared C libraries exist anywhere in the image.
            </p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-sky-400 text-sm flex items-center gap-2">
              <Cpu className="w-4 h-4" /> Total LKM Immunity (CONFIG_MODULES=n)
            </div>
            <p className="text-slate-400 leading-relaxed">
              Loadable kernel module support is permanently compiled out of the kernel. The{' '}
              <code className="text-slate-200 font-mono">init_module</code> and{' '}
              <code className="text-slate-200 font-mono">finit_module</code> syscalls do not exist, making LKM rootkit
              insertion architecturally impossible.
            </p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-amber-400 text-sm flex items-center gap-2">
              <Zap className="w-4 h-4" /> Sub-1.2s UEFI Stub Boot into RAM
            </div>
            <p className="text-slate-400 leading-relaxed">
              Built with <code className="text-slate-200 font-mono">CONFIG_EFI_STUB=y</code>, UEFI firmware or QEMU/KVM
              boots <code className="text-slate-200 font-mono">axonwall-edge-sku-vm-virtio.efi</code> (~7.0 MB) directly
              into RAM in under 1.2 seconds without GRUB or any writable disk partition.
            </p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-purple-400 text-sm flex items-center gap-2">
              <Layers className="w-4 h-4" /> Pure-Go PID 1 Lifecycle
            </div>
            <p className="text-slate-400 leading-relaxed">
              On boot, <code className="text-slate-200 font-mono">engine/pid1.go</code> mounts{' '}
              <code className="text-slate-200 font-mono">/proc</code>, <code className="text-slate-200 font-mono">/sys</code>,
              and <code className="text-slate-200 font-mono">/dev</code>, applies hardened kernel sysctls, reaps zombie
              processes, pets the hardware watchdog, and drives all networking via raw Linux netlink sockets.
            </p>
          </div>
        </div>
      </section>

      {/* 2. Pure-Go Netlink Data Plane & Dual-Stack IPv6 */}
      <section id="netlink-ipv6" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Globe className="w-6 h-6 text-sky-400" /> 2. Pure-Go Netlink Engine &amp; Dual-Stack IPv6
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Because no userland CLI tools exist inside the Edge UKI, <code className="text-emerald-400 font-mono">axonwall-satellite</code>{' '}
          programs the Linux kernel directly over raw netlink sockets:
        </p>

        <ul className="space-y-3 text-xs text-slate-300">
          <li className="p-4 rounded-xl bg-slate-900 border border-slate-800">
            <strong className="text-white block mb-1">
              1. Pure-Go <code className="text-emerald-400 font-mono">NETLINK_NFTABLES</code> Compiler (<code className="font-mono">engine/nft_netlink.go</code>)
            </strong>
            Translates desired firewall state into atomic netlink batch transactions—creating{' '}
            <code className="text-slate-200 font-mono">table inet axonwall</code>, hardware-offloaded fastpath flowtables
            (<code className="text-slate-200 font-mono">CONFIG_NF_FLOW_TABLE_INET=y</code>), stateful conntrack chains,
            SNAT masquerading, DNAT port forwards, and RFC 4890 Essential ICMPv6 Neighbor Discovery/PMTUD preservation.
          </li>
          <li className="p-4 rounded-xl bg-slate-900 border border-slate-800">
            <strong className="text-white block mb-1">
              2. Pure-Go <code className="text-sky-400 font-mono">NETLINK_GENERIC</code> WireGuard Engine (<code className="font-mono">engine/wg_netlink.go</code>)
            </strong>
            Creates WireGuard interfaces, injects private keys, and updates peer endpoints and Rosenpass Post-Quantum
            PSKs directly via Generic Netlink without <code className="text-slate-200 font-mono">wg</code> or{' '}
            <code className="text-slate-200 font-mono">iproute2</code> binaries.
          </li>
          <li className="p-4 rounded-xl bg-slate-900 border border-slate-800">
            <strong className="text-white block mb-1">
              3. Full Dual-Stack IPv6 &amp; Carrier Engine (<code className="font-mono">engine/ipv6.go</code> &amp; <code className="font-mono">engine/dhcp4.go</code>)
            </strong>
            Supports per-interface IPv6 modes (<code className="text-slate-200 font-mono">disabled</code>,{' '}
            <code className="text-slate-200 font-mono">auto</code>, <code className="text-slate-200 font-mono">static</code>,{' '}
            <code className="text-slate-200 font-mono">delegated</code>, <code className="text-slate-200 font-mono">ula-only</code>),
            including a native RFC 8415 DHCPv6 client (<code className="text-slate-200 font-mono">IA_NA</code> address
            assignment + <code className="text-slate-200 font-mono">IA_PD</code> prefix delegation with deterministic{' '}
            <code className="text-slate-200 font-mono">DUID-LL</code>), deterministic RFC 4193 ULA subnet generation, and
            an embedded RFC 4861/8106 Router Advertisement (RA + RDNSS) daemon for downstream LAN segments.
          </li>
          <li className="p-4 rounded-xl bg-slate-900 border border-slate-800">
            <strong className="text-white block mb-1">
              4. Real-Time Memory Flow &amp; Drop Telemetry (<code className="font-mono">engine/flow_streamer.go</code>)
            </strong>
            Harvests live conntrack flows (<code className="text-slate-200 font-mono">/proc/net/nf_conntrack</code>) and
            dropped packet logs (<code className="text-slate-200 font-mono">/dev/kmsg</code>) in RAM and streams compressed
            batches (<code className="text-slate-200 font-mono">EDGE_FLOW_BATCH</code>) over mTLS WebSockets to the
            central Axonwall Hub.
          </li>
        </ul>
      </section>

      {/* 3. Autonomous Pure-Go Cloud-Init */}
      <section id="cloud-init" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Terminal className="w-6 h-6 text-emerald-400" /> 3. Autonomous Zero-Touch Cloud-Init (Zero Python)
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          The PID 1 binary includes a complete, pure-Go Cloud-Init engine (<code className="text-emerald-400 font-mono">engine/cloudinit.go</code>)
          that provisions the unmodified release <code className="text-slate-200 font-mono">axonwall-edge-sku-vm-virtio.efi</code>{' '}
          image across any hypervisor or public cloud:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <div className="font-bold text-white">NoCloud &amp; ConfigDrive</div>
            <p className="text-slate-400 leading-relaxed">
              Scans <code className="text-slate-200 font-mono">/sys/class/block</code> for <code className="text-slate-200 font-mono">cidata</code>{' '}
              or <code className="text-slate-200 font-mono">config-2</code> volumes, mounts <code className="text-slate-200 font-mono">iso9660</code>/<code className="text-slate-200 font-mono">vfat</code>{' '}
              read-only (<code className="text-slate-200 font-mono">MS_RDONLY|MS_NOEXEC</code>), parses{' '}
              <code className="text-slate-200 font-mono">user-data</code> &amp; <code className="text-slate-200 font-mono">network-config</code>{' '}
              (v1 &amp; v2 Netplan), and immediately unmounts.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <div className="font-bold text-white">QEMU fw_cfg Direct Seed</div>
            <p className="text-slate-400 leading-relaxed">
              Reads <code className="text-slate-200 font-mono">/sys/firmware/qemu_fw_cfg/by_name/opt/cloud-init/user-data/raw</code>{' '}
              directly from the hypervisor without attaching any virtual CD-ROM or block device.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <div className="font-bold text-white">Cloud IMDS (169.254.169.254)</div>
            <p className="text-slate-400 leading-relaxed">
              Auto-acquires an RFC 2131 DHCPv4 lease on the primary NIC and probes OpenStack, Hetzner, DigitalOcean,
              AWS EC2 (IMDSv2 token + IMDSv1), GCP, and Azure metadata endpoints.
            </p>
          </div>
        </div>

        <CodeBlock
          title="Example #cloud-config for Zero-Touch Edge UKI Provisioning"
          language="yaml"
          code={`#cloud-config
hostname: edge-fw-nyc-01
axonwall:
  hub: wss://10.0.0.2:2966/ws/satellite
  id: edge-fw-nyc-01
  token: ztp_axon_9f8e7d6c5b4a3f2e1d0c
  sku: sku-vm-virtio
  interfaces:
    - name: wan
      device: eth0
      role: wan
      address: dhcp
      ipv6Mode: auto
    - name: lan
      device: eth1
      role: lan
      address: 10.10.0.1/24
      ipv6Mode: delegated
  ha:
    enabled: true
    role: master
    syncInterface: eth1
    peerIp: 10.10.0.2
    virtualIps:
      - interface: eth1
        address: 10.10.0.254/24`}
        />
      </section>

      {/* 4. Active-Standby Edge HA & Hosted Edge Orchestration */}
      <section id="edge-ha-host" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <ArrowRightLeft className="w-6 h-6 text-amber-400" /> 4. Active-Standby Edge HA &amp; Hosted Edge VM Mode
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          The Edge NGFW supports two deployment topologies—both with sub-second Active-Standby High Availability and
          hardware watchdog enforcement (<code className="text-slate-200 font-mono">/dev/watchdog</code> for QEMU{' '}
          <code className="text-slate-200 font-mono">i6300esb</code> or Intel <code className="text-slate-200 font-mono">iTCO_wdt</code>):
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-white text-sm">Mode A: Dedicated Bare-Metal / Cloud VM</div>
            <p className="text-slate-400 leading-relaxed">
              Flash or boot <code className="text-slate-200 font-mono">axonwall-edge-*.efi</code> directly on dedicated
              Intel N100/Xeon/ARM64 hardware or cloud VMs. Pair two Edge nodes with <code className="text-slate-200 font-mono">EdgeHAEngine</code>{' '}
              for UDP heartbeat monitoring, automatic WAN carrier self-fencing on standby, LAN VIP takeover, and stateful
              conntrack synchronization.
            </p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-white text-sm">Mode B: Hosted Edge VM Inside Axonwall Host</div>
            <p className="text-slate-400 leading-relaxed">
              An Axonwall host binds the physical WAN port into an isolated <code className="text-slate-200 font-mono">br-wan</code>{' '}
              bridge with host netfilter bypass and zero host IP addresses, then boots the Edge UKI directly inside a
              pinned QEMU/KVM micro-VM (<code className="text-slate-200 font-mono">-kernel axonwall-edge-sku-vm-virtio.efi</code>). Untrusted WAN
              packets terminate inside the zero-shell micro-VM before ever reaching the host OS.
            </p>
          </div>
        </div>
      </section>

      {/* 5. Hardware SKU Profiles */}
      <section id="sku-profiles" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Server className="w-6 h-6 text-emerald-400" /> 5. Manufacturing Hardware SKU Profiles
        </h2>

        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-900/90 border-b border-slate-800 text-slate-300">
                <th className="py-3 px-4 font-bold">SKU Profile</th>
                <th className="py-3 px-4 font-bold">Target Platform</th>
                <th className="py-3 px-4 font-bold">Built-in Monolithic Drivers</th>
                <th className="py-3 px-4 font-bold">Compiler Tuning</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              <tr>
                <td className="py-3 px-4 font-mono text-emerald-400 font-semibold">sku-vm-virtio</td>
                <td className="py-3 px-4">KVM / QEMU / Proxmox / Cloud Edge</td>
                <td className="py-3 px-4 font-mono">virtio_net, virtio_pci, i6300esb</td>
                <td className="py-3 px-4 font-mono">-march=x86-64, GOAMD64=v1</td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-mono text-sky-400 font-semibold">sku-x86-intel-n100-i226</td>
                <td className="py-3 px-4">Intel Alder Lake-N (N100/N305) Branch Appliance</td>
                <td className="py-3 px-4 font-mono">igc (2.5GbE i226), igb, e1000e, iTCO_wdt</td>
                <td className="py-3 px-4 font-mono">-march=x86-64-v3 -mtune=alderlake</td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-mono text-amber-400 font-semibold">sku-x86-enterprise-10g-25g</td>
                <td className="py-3 px-4">1U/2U Xeon &amp; EPYC Rack NGFW</td>
                <td className="py-3 px-4 font-mono">ixgbe (10G), i40e (25/40G), ice (100G), mlx5_core</td>
                <td className="py-3 px-4 font-mono">-march=x86-64-v3, GOAMD64=v3</td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-mono text-purple-400 font-semibold">sku-arm64-router</td>
                <td className="py-3 px-4">ARM64 SoC Gateway (MT7988A / Marvell Armada)</td>
                <td className="py-3 px-4 font-mono">mt7530_dsa, mtk_eth_soc, mvpp2</td>
                <td className="py-3 px-4 font-mono">-mcpu=cortex-a73+crypto, GOARCH=arm64</td>
              </tr>
            </tbody>
          </table>
        </div>

        <CodeBlock
          title="Download & Boot the Official v0.11.32 Edge UKI in QEMU/KVM"
          language="bash"
          code={`# 1. Download the signed Edge UKI and initramfs from GitHub Releases
wget https://github.com/axonwall/axonwall/releases/download/v0.11.32/axonwall-edge-sku-vm-virtio.efi
wget https://github.com/axonwall/axonwall/releases/download/v0.11.32/axonwall-edge-sku-vm-virtio.efi.sha256
sha256sum -c axonwall-edge-sku-vm-virtio.efi.sha256

# 2. Boot directly into RAM (< 1.2s boot time, zero disk required)
qemu-system-x86_64 -enable-kvm -m 512M -smp 2 \\
  -kernel axonwall-edge-sku-vm-virtio.efi \\
  -device i6300esb -watchdog-action reset \\
  -netdev user,id=wan0 -device virtio-net-pci,netdev=wan0 \\
  -nographic`}
        />

        <Callout type="tip" title="Manage from Fleet Console, Neovim TUI, or CLI">
          Orchestrate Hosted and Dedicated Edge NGFW nodes from the Web Console under{' '}
          <code className="font-mono text-emerald-300">/fleet</code>, in the Neovim Super Configurator via{' '}
          <code className="font-mono text-emerald-300">axonwall-config</code>, or declaratively via{' '}
          <code className="font-mono text-emerald-300">/etc/axonwall/edge.yaml</code>.
        </Callout>
      </section>
    </div>
  );
}
