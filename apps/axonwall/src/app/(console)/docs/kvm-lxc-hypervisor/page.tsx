import React from 'react';
import Link from 'next/link';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';
import {
  Cpu,
  Boxes,
  Layers,
  Network,
  Shield,
  HardDrive,
  Server,
  Terminal,
  CheckCircle2,
  Workflow,
} from 'lucide-react';

export const metadata = {
  title: 'KVM/QEMU Virtual Machines, LXC & Hosted Edge Hypervisor | Axonwall Documentation',
  description:
    'Technical documentation for the Axonwall Hypervisor (core-virt): Type-1 KVM/QEMU VMs, OVMF Secure Boot + swtpm TPM 2.0, VirtioFS ZFS shares, CPU Pinning/NUMA/Hugepages, ZFS Zero-Copy Clones & Live Migration, Libvirt XML, Per-VM Security Groups, unprivileged LXC containers, PCIe VFIO/SR-IOV passthrough, and Hosted Edge UKI.',
};

export default function KvmLxcHypervisorDocPage() {
  return (
    <div className="space-y-12">
      {/* Page Header */}
      <div className="space-y-4 border-b border-slate-800 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <Cpu className="w-3.5 h-3.5" /> Core Role: core-virt • Type-1 KVM/QEMU &amp; LXC Engine
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Axonwall Hypervisor: KVM/QEMU VMs, LXC &amp; Hosted Edge UKI
        </h1>
        <p className="text-base text-slate-400 leading-relaxed max-w-3xl">
          Enabling the <code className="text-emerald-400 font-mono">core-virt</code> Core Role transforms any Axonwall
          appliance into a converged Type-1 KVM/QEMU and LXC virtualization platform backed directly by OpenZFS storage
          and stateful <code className="text-slate-200 font-mono">nftables</code> microsegmentation. Every VM, system
          container, PCIe passthrough binding, VXLAN overlay fabric, Hosted Edge NGFW micro-VM, and backup schedule is
          declared in <code className="text-emerald-400 font-mono">/etc/axonwall/virt.yaml</code> and reconciled
          atomically by <code className="text-slate-200 font-mono">axonwalld</code>.
        </p>
      </div>

      {/* 1. Type-1 KVM/QEMU Virtual Machines */}
      <section id="kvm-vms" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Server className="w-6 h-6 text-emerald-400" /> 1. Type-1 KVM/QEMU Virtual Machines
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          The <code className="text-emerald-400 font-mono">VirtManager</code> engine (<code className="text-slate-200 font-mono">engine/virt.go</code>)
          compiles each <code className="text-slate-200 font-mono">VirtualMachineSchema</code> entry (<code className="text-slate-200 font-mono">vmid</code>{' '}
          <code className="text-slate-200 font-mono">100–99999</code>) into deterministic QEMU hardware topologies
          without heavy middleware daemons, persisting runtime specs at{' '}
          <code className="text-slate-200 font-mono">/var/lib/axonwall/virt-specs.json</code> and guarding concurrent
          lifecycle transitions with Proxmox-style asynchronous <code className="text-emerald-400 font-mono">UPID</code>{' '}
          task tracking (<code className="text-slate-200 font-mono">/var/log/axonwall/tasks</code>).
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-emerald-400 text-sm flex items-center gap-2">
              <Cpu className="w-4 h-4" /> OVMF UEFI, Secure Boot &amp; TPM 2.0
            </div>
            <p className="text-slate-400 leading-relaxed">
              Choose <code className="text-slate-200 font-mono">bios: &quot;ovmf&quot;</code> (UEFI with persistent NVRAM
              efivars) or legacy <code className="text-slate-200 font-mono">seabios</code>, enable{' '}
              <code className="text-slate-200 font-mono">secureBoot: true</code>, and attach an emulated{' '}
              <code className="text-slate-200 font-mono">swtpm</code> TPM 2.0 socket (<code className="text-slate-200 font-mono">tpm2: true</code>)
              for Windows 11, BitLocker, and measured-boot Linux guests alongside <code className="text-slate-200 font-mono">host</code>{' '}
              or <code className="text-slate-200 font-mono">x86-64-v2-AES</code> CPU passthrough and virtio memory ballooning.
            </p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-sky-400 text-sm flex items-center gap-2">
              <HardDrive className="w-4 h-4" /> OpenZFS ZVOL Backing Disks &amp; QoS
            </div>
            <p className="text-slate-400 leading-relaxed">
              Each virtual disk (<code className="text-slate-200 font-mono">VmDiskSchema</code>) auto-provisions a raw
              OpenZFS ZVOL on the target pool (<code className="text-slate-200 font-mono">virtio</code>,{' '}
              <code className="text-slate-200 font-mono">scsi</code>, <code className="text-slate-200 font-mono">nvme</code>,{' '}
              <code className="text-slate-200 font-mono">sata</code>, or <code className="text-slate-200 font-mono">ide</code>)
              with native TRIM/UNMAP (<code className="text-slate-200 font-mono">discard: true</code>), cache mode
              control, and per-disk read/write IOPS throttling (<code className="text-slate-200 font-mono">iopsReadLimit</code>{' '}
              / <code className="text-slate-200 font-mono">iopsWriteLimit</code>).
            </p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-amber-400 text-sm flex items-center gap-2">
              <Network className="w-4 h-4" /> Multi-Mode NICs, Guest Agent &amp; Cloud-Init
            </div>
            <p className="text-slate-400 leading-relaxed">
              Attach <code className="text-slate-200 font-mono">virtio</code>, <code className="text-slate-200 font-mono">vmxnet3</code>,
              or <code className="text-slate-200 font-mono">e1000e</code> NICs via Linux bridges (with 802.1Q{' '}
              <code className="text-slate-200 font-mono">vlanTag</code>, per-VNIC <code className="text-slate-200 font-mono">firewall</code>,
              and <code className="text-slate-200 font-mono">rateLimitMbps</code>),{' '}
              <code className="text-slate-200 font-mono">macvtap-passthru</code>, or direct{' '}
              <code className="text-slate-200 font-mono">vfio</code>. Per-VM <code className="text-slate-200 font-mono">cloudInit</code>{' '}
              injects SSH keys, static/DHCP networking, and custom user-data while QEMU Guest Agent (<code className="text-slate-200 font-mono">agent: true</code>)
              provides clean fsfreeze snapshots and live IP discovery.
            </p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-purple-400 text-sm flex items-center gap-2">
              <Terminal className="w-4 h-4" /> HTML5 noVNC &amp; Serial WebSocket Console
            </div>
            <p className="text-slate-400 leading-relaxed">
              Zero external TCP VNC ports are ever opened on the host. Instead, QEMU binds local Unix domain sockets under{' '}
              <code className="text-slate-200 font-mono">/run/axonwall/vnc/vm-&lt;vmid&gt;.sock</code> and{' '}
              <code className="text-slate-200 font-mono">/run/axonwall/serial/vm-&lt;vmid&gt;.sock</code>, and{' '}
              <code className="text-slate-200 font-mono">ConsoleProxy</code> (<code className="text-slate-200 font-mono">engine/novnc.go</code>)
              streams authenticated RFC 6455 WebSocket frames over <code className="text-emerald-300 font-mono">/v1/virt/console/ws</code>{' '}
              with strict same-origin verification.
            </p>
          </div>
        </div>
      </section>

      {/* 1b. VirtioFS, CPU Pinning/NUMA/Hugepages, Zero-Copy Clones, Live Migration & Libvirt XML */}
      <section id="clones-migration-xml" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Layers className="w-6 h-6 text-emerald-400" /> Enterprise Proxmox &amp; Libvirt Parity: VirtioFS, Clones, Live Migration &amp; XML
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Axonwall matches and surpasses dedicated Type-1 hypervisors by integrating zero-copy OpenZFS primitives,
          vhost-user shared memory filesystems, canonical Libvirt XML compilation, and per-VNIC stateful Netfilter
          microsegmentation:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <h3 className="font-bold text-emerald-400 text-sm">VirtioFS Host ZFS Shares</h3>
            <p className="text-slate-400 leading-relaxed">
              Declare <code className="text-slate-200 font-mono">virtioFsShares[]</code> (<code className="font-mono">tag</code>,{' '}
              <code className="font-mono">hostPath</code>, <code className="font-mono">cacheMode</code>) to mount host
              OpenZFS datasets directly inside Linux &amp; Windows VMs via <code className="text-slate-200 font-mono">virtiofsd</code>{' '}
              vhost-user shared memory—bypassing SMB/NFS network overhead completely.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <h3 className="font-bold text-sky-400 text-sm">CPU Pinning, NUMA &amp; Hugepages</h3>
            <p className="text-slate-400 leading-relaxed">
              Pin vCPU threads to physical cores (<code className="text-slate-200 font-mono">cpuAffinity</code>), expose
              guest NUMA topologies (<code className="text-slate-200 font-mono">numaEnabled: true</code>), and back guest
              RAM with <code className="text-slate-200 font-mono">2M</code> or <code className="text-slate-200 font-mono">1G</code>{' '}
              Hugepages for deterministic latency.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <h3 className="font-bold text-purple-400 text-sm">Zero-Copy ZFS Linked Clones</h3>
            <p className="text-slate-400 leading-relaxed">
              Clone any VM template in milliseconds via <code className="text-slate-200 font-mono">zfs snapshot</code> +{' '}
              <code className="text-slate-200 font-mono">zfs clone</code> (<code className="text-emerald-300 font-mono">axonwallctl virt clone</code>),
              consuming zero additional ZFS blocks until copy-on-write divergence.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <h3 className="font-bold text-amber-400 text-sm">QMP + ZFS Live Migration</h3>
            <p className="text-slate-400 leading-relaxed">
              Migrate running VMs across clustered Axonwall nodes (<code className="text-emerald-300 font-mono">axonwallctl virt migrate</code>)
              combining incremental ZFS ZVOL streaming with QEMU QMP RAM dirty-page convergence.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <h3 className="font-bold text-rose-300 text-sm">Per-VM nftables Security Groups</h3>
            <p className="text-slate-400 leading-relaxed">
              Attach reusable <code className="text-slate-200 font-mono">vmSecurityGroups[]</code> directly to each VM
              NIC (<code className="text-slate-200 font-mono">tap&lt;vmid&gt;i&lt;idx&gt;</code>), enforcing East-West
              zero-trust microsegmentation even between VMs on the same L2 bridge.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <h3 className="font-bold text-teal-300 text-sm">Libvirt Domain XML Compiler</h3>
            <p className="text-slate-400 leading-relaxed">
              Export or inspect canonical <code className="text-slate-200 font-mono">&lt;domain type=&apos;kvm&apos;&gt;</code>{' '}
              Libvirt XML (<code className="text-emerald-300 font-mono">axonwallctl virt xml &lt;vmid&gt;</code> /{' '}
              <code className="text-purple-300 font-mono">axonwall://virt/libvirt-domains</code>) for full{' '}
              <code className="text-slate-200 font-mono">virsh</code> ecosystem compatibility.
            </p>
          </div>
        </div>
      </section>

      {/* 2. Lightweight LXC System Containers */}
      <section id="lxc-containers" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Boxes className="w-6 h-6 text-sky-400" /> 2. Lightweight LXC System Containers
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          For near-zero overhead Linux system services that share the hardened Axonwall kernel while retaining full{' '}
          <code className="text-slate-200 font-mono">systemd</code> / OpenRC init userlands,{' '}
          <code className="text-emerald-400 font-mono">LxcContainerSchema</code> provisions isolated containers (<code className="text-slate-200 font-mono">ctid</code>{' '}
          <code className="text-slate-200 font-mono">100–99999</code>) directly onto native OpenZFS filesystem datasets:
        </p>

        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-900/90 border-b border-slate-800 text-slate-300">
                <th className="py-3 px-4 font-bold">Schema Field</th>
                <th className="py-3 px-4 font-bold">Default</th>
                <th className="py-3 px-4 font-bold">Isolation &amp; Storage Behavior</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              <tr>
                <td className="py-3 px-4 font-mono text-emerald-400 font-semibold">unprivileged</td>
                <td className="py-3 px-4 font-mono">true</td>
                <td className="py-3 px-4">
                  Maps container UID <code className="font-mono">0</code> into an unprivileged high UID/GID range via
                  Linux user namespaces, neutralizing root-escape vectors.
                </td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-mono text-sky-400 font-semibold">rootfsPool / rootfsSizeGb</td>
                <td className="py-3 px-4 font-mono">&quot;tank&quot; / 8 GiB</td>
                <td className="py-3 px-4">
                  Creates a dedicated ZFS dataset with <code className="font-mono">refquota</code> enforcement, instant
                  copy-on-write snapshots, and <code className="font-mono">lz4</code>/<code className="font-mono">zstd</code> compression.
                </td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-mono text-amber-400 font-semibold">mountPoints[]</td>
                <td className="py-3 px-4 font-mono">[]</td>
                <td className="py-3 px-4">
                  Declarative host-to-container bind mounts (<code className="font-mono">hostPath</code> &rarr;{' '}
                  <code className="font-mono">mountPath</code>) with optional <code className="font-mono">readOnly: true</code>{' '}
                  enforcement for shared ZFS NAS datasets.
                </td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-mono text-purple-400 font-semibold">features[]</td>
                <td className="py-3 px-4 font-mono">[&quot;nesting&quot;]</td>
                <td className="py-3 px-4">
                  Fine-grained capability toggles (<code className="font-mono">nesting</code>,{' '}
                  <code className="font-mono">keyctl</code>, <code className="font-mono">fuse</code>) for running nested
                  Podman/Docker engines or FUSE filesystems safely inside LXC.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* 3. PCIe VFIO Passthrough, SR-IOV & VXLAN SDN */}
      <section id="vfio-sriov" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Layers className="w-6 h-6 text-amber-400" /> 3. PCIe VFIO Passthrough, SR-IOV &amp; VXLAN SDN
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Hardware accelerators (GPUs/NPUs for local AI inference, NVMe controllers, and 10G/25G/100G NICs) and
          multi-node Layer-2 tenant networks are first-class citizens in <code className="text-emerald-400 font-mono">virt.yaml</code>:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">IOMMU &amp; vfio-pci Binding</h3>
            <p className="text-slate-400 leading-relaxed">
              <code className="text-slate-200 font-mono">engine/vfio.go</code> enumerates{' '}
              <code className="text-slate-200 font-mono">/sys/kernel/iommu_groups</code>, verifies clean IOMMU group
              isolation for each PCI <code className="text-slate-200 font-mono">bdf</code> (<code className="text-slate-200 font-mono">0000:xx:xx.x</code>),
              and dynamically unbinds host drivers to bind <code className="text-emerald-300 font-mono">vfio-pci</code>.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">SR-IOV Virtual Functions</h3>
            <p className="text-slate-400 leading-relaxed">
              Setting <code className="text-slate-200 font-mono">sriovNumVfs</code> on Intel X710/E810 or Mellanox
              ConnectX physical functions programs <code className="text-slate-200 font-mono">sriov_numvfs</code> in
              sysfs so VMs receive line-rate hardware Virtual Functions with near-zero CPU interrupt overhead.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">VXLAN EVPN/SDN Overlay</h3>
            <p className="text-slate-400 leading-relaxed">
              <code className="text-slate-200 font-mono">VxlanZoneSchema</code> stretches isolated Layer-2 segments
              across HA or branch Axonwall nodes using 24-bit VNIs (<code className="text-slate-200 font-mono">1–16777215</code>)
              over UDP <code className="text-slate-200 font-mono">4789</code> (unicast <code className="text-slate-200 font-mono">peers</code>{' '}
              or multicast) with automatic <code className="text-slate-200 font-mono">1450</code> MTU clamping.
            </p>
          </div>
        </div>
      </section>

      {/* 4. Hosted Virtual Edge NGFW UKI */}
      <section id="hosted-edge" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Shield className="w-6 h-6 text-emerald-400" /> 4. Hosted Virtual Edge NGFW UKI (<code className="font-mono text-emerald-400">hostedEdge</code>)
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          For maximum perimeter isolation on a single physical box, <code className="text-emerald-400 font-mono">/etc/axonwall/virt.yaml</code>{' '}
          includes the <code className="text-slate-200 font-mono">hostedEdge</code> stanza (<code className="text-slate-200 font-mono">HostedEdgeConfigSchema</code>).
          When enabled, the host places its physical WAN interface into <code className="text-slate-200 font-mono">wan-delegated</code>{' '}
          mode (an isolated <code className="text-slate-200 font-mono">br-wan</code> bridge,{' '}
          <code className="text-slate-200 font-mono">macvtap-passthru</code>, or direct <code className="text-slate-200 font-mono">vfio</code>{' '}
          PCI passthrough with zero host IPv4/IPv6 addresses) and boots the{' '}
          <Link href="/docs/edge-uki-ngfw" className="text-emerald-400 hover:text-emerald-300 underline underline-offset-4">
            Super-Slim Edge NGFW UEFI UKI
          </Link>{' '}
          (<code className="text-slate-200 font-mono">axonwall-satellite</code> as pure-Go PID 1 with{' '}
          <code className="text-slate-200 font-mono">CONFIG_MODULES=n</code> and zero shells) inside a diskless RAM-only
          front-door micro-VM.
        </p>

        <Callout type="info" title="Dual A/B UKI Slots & Delegated-WAN Blast Containment">
          Untrusted internet frames terminate inside the stateless 256 MiB micro-VM before ever reaching the host Linux
          network stack. Upgrades toggle cleanly between <code className="font-mono text-sky-300">ukiSlot: &quot;A&quot;</code>{' '}
          and <code className="font-mono text-sky-300">ukiSlot: &quot;B&quot;</code> with hardware{' '}
          <code className="font-mono text-sky-300">i6300esb</code> watchdog auto-reset and optional Active-Standby Edge
          HA over transit VLANs <code className="font-mono text-sky-300">4000</code>/<code className="font-mono text-sky-300">4001</code>.
        </Callout>
      </section>

      {/* 5. Cloud-Init & Deduplicated Workload Backups */}
      <section id="cloud-init-backups" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Workflow className="w-6 h-6 text-purple-400" /> 5. Deduplicated Backups &amp; Appliance Cloud-Init Export
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Axonwall pairs scheduled workload disaster recovery (<code className="text-slate-200 font-mono">WorkloadBackupJobSchema</code>)
          with full-appliance <code className="text-emerald-400 font-mono">#cloud-config</code> Golden Image cloning:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-white text-sm flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" /> ZFS, S3 &amp; Proxmox Backup Server (PBS)
            </div>
            <p className="text-slate-400 leading-relaxed">
              Schedule cron jobs targeting <code className="text-slate-200 font-mono">all</code> or{' '}
              <code className="text-slate-200 font-mono">selected</code> VMIDs/CTIDs with QEMU Guest Agent fsfreeze,{' '}
              <code className="text-slate-200 font-mono">zstd</code> compression, optional client-side encryption, and
              Grandfather-Father-Son (GFS) retention (<code className="text-slate-200 font-mono">keepLast</code>,{' '}
              <code className="text-slate-200 font-mono">keepDaily</code>, <code className="text-slate-200 font-mono">keepWeekly</code>,{' '}
              <code className="text-slate-200 font-mono">keepMonthly</code>) to <code className="text-slate-200 font-mono">local-zfs</code>,{' '}
              S3-compatible object storage (<code className="text-slate-200 font-mono">s3</code>), or Proxmox Backup Server (<code className="text-slate-200 font-mono">pbs</code>).
            </p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-white text-sm flex items-center gap-2">
              <Terminal className="w-4 h-4 text-sky-400" /> Full-Appliance Cloud-Init Import &amp; Export
            </div>
            <p className="text-slate-400 leading-relaxed">
              <code className="text-slate-200 font-mono">axonwallctl cloudinit export</code> serializes the running
              appliance&apos;s entire <code className="text-slate-200 font-mono">DesiredState</code> (including VMs,
              containers, ZFS topology, and OS users) into a portable <code className="text-slate-200 font-mono">#cloud-config</code>{' '}
              seed or bootable ISO9660 NoCloud <code className="text-slate-200 font-mono">cidata.iso</code>—redacting
              passwords, WireGuard keys, and tokens by default (<code className="text-slate-200 font-mono">--redact</code>)
              or stripping MAC/disk serials via <code className="text-slate-200 font-mono">--template</code>.
            </p>
          </div>
        </div>

        <CodeBlock
          title="/etc/axonwall/virt.yaml"
          language="yaml"
          code={`virt:
  enabled: true
  defaultPool: "tank"
  isoPool: "tank"

  pciDevices:
    - bdf: "0000:03:00.0"
      iommuGroup: 14
      driver: "vfio-pci"
      sriovNumVfs: 4
      description: "Intel E810-XXVDA2 25GbE SR-IOV PF0"

  vxlanZones:
    - name: "vx-dmz-east"
      vni: 10400
      peers: ["10.255.0.2"]
      underlayInterface: "lan"
      port: 4789
      bridge: "br-vx400"
      mtu: 1450
      enabled: true

  vms:
    - vmid: 101
      name: "win11-secops-wks"
      osType: "windows"
      bios: "ovmf"
      secureBoot: true
      tpm2: true
      sockets: 1
      cores: 8
      cpuType: "host"
      memoryMb: 16384
      balloonMinMb: 8192
      watchdog: "i6300esb"
      agent: true
      autostart: true
      haManaged: true
      disks:
        - name: "disk0"
          pool: "tank"
          sizeGb: 128
          bus: "nvme"
          cache: "none"
          discard: true
          iopsReadLimit: 50000
          iopsWriteLimit: 25000
          backup: true
      nics:
        - bridge: "br-vx400"
          model: "virtio"
          vlanTag: 40
          firewall: true
          queues: 4
      cloudInit:
        user: "secadmin"
        ipConfig: "10.40.0.25/24"
        gateway: "10.40.0.1"
        nameservers: ["10.40.0.1"]
        sshAuthorizedKeys:
          - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleSecOpsAdminKey secops@axonwall"

  containers:
    - ctid: 201
      hostname: "netbox-ipam"
      template: "debian-12-standard"
      unprivileged: true
      cores: 2
      memoryMb: 2048
      swapMb: 512
      rootfsPool: "tank"
      rootfsSizeGb: 16
      features: ["nesting", "keyctl"]
      mountPoints:
        - hostPath: "/mnt/tank/backups/netbox"
          mountPath: "/var/backups/netbox"
          readOnly: false
      nics:
        - bridge: "br0"
          model: "virtio"
          firewall: true
      bpfToken:
        enabled: true
        preset: "networking-safe"
      autostart: true

  backupJobs:
    - name: "nightly-vault-s3"
      scheduleCron: "0 1 * * *"
      targetType: "all"
      storagePool: "tank"
      destinationType: "s3"
      s3Endpoint: "https://s3.axonwall.lan:9000"
      s3Bucket: "axonwall-vm-backups"
      compression: "zstd"
      retention:
        keepLast: 5
        keepDaily: 7
        keepWeekly: 4
        keepMonthly: 12
      enabled: true

hostedEdge:
  enabled: true
  placement: "hosted"
  ukiSlot: "A"
  skuProfile: "sku-vm-virtio"
  vcpus: 2
  memoryMiB: 256
  wan:
    hostDevice: "eth0"
    bridgeName: "br-wan"
    attachMode: "bridge"
    ipv4Mode: "dhcp"
    ipv6Mode: "auto"
    ipv6RequestPrefix: 56
  lan:
    bridgeName: "br-lan"
    edgeAddress: "10.0.0.1/24"
    hostAddress: "10.0.0.2/24"
    ipv6Mode: "delegated"`}
        />

        <CodeBlock
          title="CLI, Cloud-Init Seed ISO Generation & Operator TUI Commands"
          language="bash"
          code={`# Validate, diff, and apply /etc/axonwall/virt.yaml changes
axonwallctl validate
axonwallctl diff
axonwallctl apply

# Export the running appliance (with secrets redacted & hardware-agnostic template mode)
# to both #cloud-config YAML and a bootable NoCloud cidata.iso seed image
axonwallctl cloudinit export --template -o seed.yaml --iso cidata.iso

# Reconcile an inbound #cloud-config user-data seed into /etc/axonwall/conf.d/99-cloudinit.yaml
axonwallctl cloudinit /etc/axonwall/cloud-config.yaml

# Open the interactive TUI directly on Tab [7] (Compute & SOC) or edit virt.yaml in Neovim
axonwall-tui
axonwall-config virt`}
        />

        <Callout type="tip" title="Manage via Web Console, Neovim TUI, or SSH Operator Console">
          Inspect live VM/LXC CPU &amp; memory telemetry, launch HTML5 noVNC consoles, configure SR-IOV/VFIO bindings,
          and trigger on-demand ZFS/PBS backups from the Web Console under{' '}
          <code className="font-mono text-emerald-300">/compute/vms</code> and{' '}
          <code className="font-mono text-emerald-300">/compute/containers</code>, or from Tab{' '}
          <code className="font-mono text-emerald-300">[7] Compute &amp; SOC</code> in <code className="font-mono text-emerald-300">axonwall-tui</code>.
        </Callout>
      </section>

      {/* Linux 6.9+ Unprivileged LXC BPF_TOKEN Delegation */}
      <section id="lxc-bpf-token" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white">
          Unprivileged LXC `BPF_TOKEN` Delegation (`CLONE_NEWUSER`) &amp; MCP Hypervisor Control
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          When an unprivileged LXC container (<code className="text-emerald-400 font-mono">unprivileged: true</code> with{' '}
          <code className="text-slate-200 font-mono">lxc.idmap = u 0 100000 65536</code>) enables{' '}
          <code className="text-emerald-400 font-mono">bpfToken.enabled: true</code> in{' '}
          <code className="text-slate-200 font-mono">/etc/axonwall/virt.yaml</code>, Axonwall&apos;s LXC compiler
          automatically injects a dedicated Linux 6.9+ delegated <code className="text-sky-400 font-mono">bpffs</code>{' '}
          mount and <code className="text-emerald-300 font-mono">LIBBPF_BPF_TOKEN_PATH=/sys/fs/bpf</code> while
          rejecting any Ring-0 tracing/kernel-memory program types (<code className="text-rose-400 font-mono">kprobe</code>,{' '}
          <code className="text-rose-400 font-mono">tracepoint</code>, <code className="text-rose-400 font-mono">lsm</code>)
          both at schema compile time and in Ring-0 via BPF-LSM:
        </p>

        <CodeBlock
          title="Compiled /var/lib/lxc/201/config Excerpt (networking-safe BPF_TOKEN)"
          language="ini"
          code={`# Linux 6.9+ Unprivileged UserNS BPF_TOKEN Delegation (Ring-0 kprobe/lsm blocked)
lxc.mount.entry = bpffs sys/fs/bpf bpf rw,nosuid,nodev,noexec,relatime,create=dir,delegate_cmds=prog_load:map_create:map_lookup_elem:map_update_elem:map_delete_elem:link_create,delegate_progs=socket_filter:sched_cls:sched_act:xdp:cgroup_skb:sk_skb:sk_msg:sock_ops,delegate_maps=hash:array:percpu_hash:percpu_array:lru_hash:lru_percpu_hash:ringbuf:lpm_trie,delegate_attachs=xdp:cgroup_inet_ingress:cgroup_inet_egress:sk_skb_stream_parser:sk_skb_stream_verdict 0 0
lxc.environment = LIBBPF_BPF_TOKEN_PATH=/sys/fs/bpf`}
        />

        <p className="text-xs text-slate-400 leading-relaxed">
          All KVM/LXC hypervisor telemetry (<code className="text-sky-400 font-mono">axonwall://virt/workloads</code>,{' '}
          <code className="text-sky-400 font-mono">mcp_inspect_virt_workloads</code>), lifecycle operations (
          <code className="text-emerald-400 font-mono">mcp_control_virt_workload</code>), and declarative LXC token
          bindings (<code className="text-emerald-400 font-mono">mcp_configure_lxc_bpf_token</code>) are exposed via the
          Axonwall MCP server under <code className="text-slate-200 font-mono">mcp:virt:read</code> and{' '}
          <code className="text-slate-200 font-mono">mcp:virt:manage</code>.
        </p>
      </section>
    </div>
  );
}
