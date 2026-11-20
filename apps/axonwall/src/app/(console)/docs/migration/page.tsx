import React from 'react';
import { UploadCloud, AlertTriangle, Layers, Boxes, Database } from 'lucide-react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'Unified Appliance Migration Studio & 9-Vendor Importer | Axonwall Documentation',
  description:
    'Complete guide to migrating from pfSense, OPNsense, Proxmox VE 8.x, TrueNAS SCALE, Cisco IOS/ASA/FTD, VyOS, MikroTik RouterOS, iptables-save, and firewalld XML to Axonwall v0.11.68: KVM/LXC workload conversion, ZFS pool & dataset import, rule shadowing detection, and non-destructive merge.',
};

export default function MigrationDocPage() {
  return (
    <div className="space-y-12">
      {/* Page Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Enterprise Tooling • 9-Vendor Unified Appliance Importer • v0.11.68
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          Migration Studio &amp; 9-Vendor Importer
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Consolidate legacy firewalls, hypervisors, and NAS appliances onto a single Linux 6.12 LTS Axonwall host.
          Powered by <code className="text-emerald-400 font-mono">@axonwall/lib/import</code>,{' '}
          <code className="text-emerald-400 font-mono">axonwallctl import</code>, and the{' '}
          <code className="text-purple-300 font-mono">mcp_import_competitor_config</code> MCP tool, Migration Studio
          parses <strong>9 vendor formats</strong>—<code className="text-white font-mono">pfSense® XML</code>,{' '}
          <code className="text-white font-mono">OPNsense® XML</code>,{' '}
          <code className="text-amber-300 font-mono">Proxmox VE 8.x</code>,{' '}
          <code className="text-sky-300 font-mono">TrueNAS SCALE</code>,{' '}
          <code className="text-white font-mono">Cisco IOS / ASA / FTD</code>,{' '}
          <code className="text-white font-mono">VyOS</code>,{' '}
          <code className="text-white font-mono">MikroTik RouterOS (.rsc)</code>,{' '}
          <code className="text-white font-mono">iptables-save</code>, and{' '}
          <code className="text-white font-mono">firewalld XML</code>—with mathematical rule-shadowing, subnet-collision
          audits, and non-destructive multi-appliance merging.
        </p>
      </div>

      {/* Supported Platforms */}
      <section id="supported-platforms" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <UploadCloud className="w-6 h-6 text-emerald-400" /> All 9 Supported Firewall, Hypervisor &amp; NAS Importers
        </h2>
        <div id="pfsense-opnsense" className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-xs">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">1. pfSense® XML (<code className="text-emerald-400 font-mono">pfsense</code>)</h3>
            <p className="text-slate-400 leading-relaxed">
              Parses <code className="text-slate-200">config.xml</code> backups: aliases, floating &amp; per-interface filter rules, DNAT port forwards + Hairpin NAT reflection, 1:1 BINAT, NPTv6, VLANs, gateways, and DHCP static reservations.
            </p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">2. OPNsense® XML (<code className="text-emerald-400 font-mono">opnsense</code>)</h3>
            <p className="text-slate-400 leading-relaxed">
              Full compatibility with OPNsense 24.x/25.x MVC + legacy XML schemas, including nested alias groups, rule categories, WireGuard peers, gateway failover groups, and Unbound host overrides.
            </p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-amber-500/40 space-y-2">
            <h3 className="font-bold text-amber-300 text-sm">3. Proxmox VE 8.x (<code className="text-amber-400 font-mono">proxmox</code>)</h3>
            <p className="text-slate-400 leading-relaxed">
              Parses <code className="text-slate-200">/etc/pve/qemu-server/*.conf</code>, <code className="text-slate-200">lxc/*.conf</code>, <code className="text-slate-200">firewall/*.fw</code>, and <code className="text-slate-200">/etc/network/interfaces</code> (<code className="text-slate-200">vmbr*</code>) into <code className="text-slate-200">virt.yaml</code>, <code className="text-slate-200">interfaces.yaml</code>, and <code className="text-slate-200">firewall.yaml</code>.
            </p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-sky-500/40 space-y-2">
            <h3 className="font-bold text-sky-300 text-sm">4. TrueNAS SCALE (<code className="text-sky-400 font-mono">truenas</code>)</h3>
            <p className="text-slate-400 leading-relaxed">
              Imports TrueNAS SCALE JSON/middleware exports: OpenZFS pool topologies (including Special NVMe VDEVs), encrypted datasets, snapshot schedules, SMB3 Time Machine/VSS shares, NFSv4 exports, and iSCSI targets into <code className="text-slate-200">storage.yaml</code>.
            </p>
          </div>

          <div id="cisco-asa" className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">5. Cisco IOS / ASA / FTD (<code className="text-emerald-400 font-mono">cisco-asa</code>)</h3>
            <p className="text-slate-400 leading-relaxed">
              Parses <code className="text-slate-200">running-config</code>: <code className="text-slate-200">object network</code>, nested <code className="text-slate-200">object-group</code> network/service hierarchies, extended ACLs, and Auto-NAT/Twice-NAT rules.
            </p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">6. VyOS (<code className="text-emerald-400 font-mono">vyos</code>)</h3>
            <p className="text-slate-400 leading-relaxed">
              Parses hierarchical brace <code className="text-slate-200">config.boot</code> trees and <code className="text-slate-200">set firewall ...</code> commands across VyOS 1.3/1.4/1.5 address/network/port groups, zones, and SNAT/DNAT.
            </p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">7. MikroTik RouterOS (<code className="text-emerald-400 font-mono">mikrotik</code>)</h3>
            <p className="text-slate-400 leading-relaxed">
              Imports RouterOS v6/v7 <code className="text-slate-200">.rsc</code> scripts (<code className="text-slate-200">/ip firewall address-list</code>, <code className="text-slate-200">filter</code>, <code className="text-slate-200">nat</code>, VLAN interfaces, and DHCP static leases).
            </p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">8. Linux iptables-save (<code className="text-emerald-400 font-mono">iptables</code>)</h3>
            <p className="text-slate-400 leading-relaxed">
              Translates <code className="text-slate-200">*filter</code> and <code className="text-slate-200">*nat</code> dumps (<code className="text-slate-200">INPUT</code>, <code className="text-slate-200">FORWARD</code>, <code className="text-slate-200">PREROUTING</code>, <code className="text-slate-200">POSTROUTING</code>, <code className="text-slate-200">multiport</code>, <code className="text-slate-200">conntrack</code>) into clean <code className="text-slate-200">firewall.yaml</code> intent.
            </p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">9. RHEL / Fedora firewalld XML (<code className="text-emerald-400 font-mono">firewalld</code>)</h3>
            <p className="text-slate-400 leading-relaxed">
              Parses <code className="text-slate-200">/etc/firewalld/zones/*.xml</code> and ipset definitions—converting zone services, rich rules, port forwards, and masquerading flags into declarative Axonwall aliases and rules.
            </p>
          </div>
        </div>
      </section>

      {/* Proxmox VE & TrueNAS SCALE Deep Dive */}
      <section id="proxmox-truenas" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Boxes className="w-6 h-6 text-amber-400" /> Consolidating Proxmox VE 8.x &amp; TrueNAS SCALE
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Axonwall eliminates the need to maintain separate OPNsense, Proxmox VE, and TrueNAS SCALE servers. You can
          import an OPNsense perimeter XML, a Proxmox VE hypervisor bundle, and a TrueNAS SCALE storage export
          sequentially using <code className="text-emerald-400 font-mono">mergeFirewallConfigs()</code> (<code className="text-slate-200 font-mono">--merge</code>)
          so all 5 core roles converge into <code className="text-slate-200 font-mono">/etc/axonwall/*.yaml</code> without overwriting existing interfaces or rules:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs">
          <div className="p-5 rounded-2xl bg-slate-900 border border-amber-500/30 space-y-2.5">
            <div className="font-bold text-amber-300 text-sm flex items-center gap-2">
              <Boxes className="w-4 h-4" /> Proxmox VE 8.x Translation Matrix
            </div>
            <ul className="space-y-1.5 text-slate-300 list-disc list-inside leading-relaxed">
              <li><strong>QEMU/KVM VMs (<code className="font-mono">[qemu:100]</code>):</strong> Maps <code className="font-mono">cores</code>, <code className="font-mono">sockets</code>, <code className="font-mono">memory</code>, <code className="font-mono">bios: ovmf</code>, <code className="font-mono">efidisk0</code> Secure Boot, <code className="font-mono">tpmstate0</code> TPM 2.0, <code className="font-mono">scsi/virtio/nvme</code> ZVOL disks, <code className="font-mono">net*</code> VLAN tags, and <code className="font-mono">hostpci*</code> VFIO devices.</li>
              <li><strong>LXC Containers (<code className="font-mono">[lxc:200]</code>):</strong> Converts <code className="font-mono">rootfs</code> ZFS datasets, <code className="font-mono">mp*</code> host bind mounts, <code className="font-mono">unprivileged: 1</code>, and <code className="font-mono">features: nesting=1</code>.</li>
              <li><strong>PVE Bridges &amp; Firewall (<code className="font-mono">cluster.fw</code>):</strong> Converts <code className="text-slate-200 font-mono">vmbr*</code> Linux bridges, <code className="font-mono">[IPSET]</code> aliases, and <code className="font-mono">[RULES]</code> security groups into <code className="font-mono">table inet axonwall</code>.</li>
            </ul>
          </div>

          <div className="p-5 rounded-2xl bg-slate-900 border border-sky-500/30 space-y-2.5">
            <div className="font-bold text-sky-300 text-sm flex items-center gap-2">
              <Database className="w-4 h-4" /> TrueNAS SCALE Translation Matrix
            </div>
            <ul className="space-y-1.5 text-slate-300 list-disc list-inside leading-relaxed">
              <li><strong>ZFS Pools &amp; Special VDEVs:</strong> Translates Stripe, Mirror, RAID-Z1/2/3, and dRAID topologies plus SLOG, L2ARC, Spare, and mirrored NVMe Special Allocation VDEVs.</li>
              <li><strong>Datasets &amp; Encryption:</strong> Preserves quotas, <code className="font-mono">recordsize</code>, <code className="font-mono">zstd/lz4</code> compression, <code className="font-mono">AES-256-GCM</code> encryption settings, and periodic snapshot tasks.</li>
              <li><strong>SMB3, NFSv4 &amp; iSCSI:</strong> Maps Samba VSS shadow copies &amp; Apple Time Machine flags, NFSv4 CIDR exports, and LIO iSCSI ZVOL extents.</li>
            </ul>
          </div>
        </div>
      </section>

      {/* Rule Shadowing & Dead Rule Detection */}
      <section id="shadowing-algorithm" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <AlertTriangle className="w-6 h-6 text-amber-400" /> Rule Shadowing &amp; Dead-Rule Detection
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Over years of maintenance, legacy firewalls accumulate redundant, obsolete, and shadowed rules. Axonwall&apos;s Policy Analyzer conducts deep mathematical set analysis before importing rules:
        </p>

        <div className="space-y-4">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-amber-400" /> How Rule Shadowing Occurs
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              Rule <strong>B</strong> is shadowed by Rule <strong>A</strong> when every packet that could match Rule B is already intercepted by Rule A preceding it:
            </p>
            <div className="p-3 rounded-lg bg-black/40 font-mono text-xs space-y-1 text-slate-300">
              <p className="text-emerald-400">Rule 1 (A): Pass TCP from 10.0.0.0/16 to any port 443</p>
              <p className="text-rose-400">Rule 2 (B): Pass TCP from 10.0.1.0/24 to any port 443 [SHADOWED]</p>
            </div>
            <p className="text-xs text-slate-400">
              Axonwall flags shadowed rules directly in the Migration UI, allowing administrators to prune dead security policies before committing them into nftables.
            </p>
          </div>

          <h3 id="subnet-collisions" className="text-base font-semibold text-white pt-2">Subnet Collision Detection</h3>
          <p className="text-xs text-slate-300 leading-relaxed">
            The analyzer verifies that imported network prefixes do not collide with active physical interfaces, preventing routing loops or accidental network severance.
          </p>
        </div>
      </section>

      {/* Cherry-Pick Selective Merge */}
      <section id="selective-merge" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Layers className="w-6 h-6 text-emerald-400" /> Non-Destructive Multi-Appliance Merge, CLI &amp; MCP Import
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Unlike legacy tools that force an &quot;all-or-nothing&quot; overwrite, Axonwall provides an interactive selective merge engine across Web UI, CLI, and MCP:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
            <span className="font-bold text-emerald-400 block mb-1">Skip Strategy</span>
            <p className="text-slate-400">Retains existing Axonwall entity and discards the imported duplicate with identical identifier.</p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
            <span className="font-bold text-sky-400 block mb-1">Overwrite Strategy</span>
            <p className="text-slate-400">Replaces the active Axonwall object with the newly imported configuration definition.</p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
            <span className="font-bold text-purple-400 block mb-1">Rename Strategy</span>
            <p className="text-slate-400">Preserves both objects by automatically suffixing the imported record with <code className="text-slate-200">_imported</code>.</p>
          </div>
        </div>

        <CodeBlock
          title="Consolidating OPNsense + Proxmox VE + TrueNAS SCALE via axonwallctl import"
          language="bash"
          code={`# 1. Dry-run auto-detection & shadowing audit on an OPNsense XML backup
axonwallctl import ./opnsense-backup.xml

# 2. Stage OPNsense perimeter rules + non-destructively merge Proxmox VE VMs/LXC & TrueNAS ZFS shares
sudo axonwallctl import ./opnsense-backup.xml --type opnsense --stage
sudo axonwallctl import ./proxmox-cluster-export.conf --type proxmox --merge --stage
sudo axonwallctl import ./truenas-scale-config.json --type truenas --merge --stage --apply

# 3. Confirm within the 120s Commit-Confirm safety window once reachability is verified
sudo axonwallctl confirm`}
        />

        <Callout type="tip" title="Web Console & Guardrailed MCP Access">
          Access the Unified Appliance Migration Studio in your running appliance at{' '}
          <code className="text-emerald-300 font-mono">System &gt; Appliance Migration Studio (/system/import)</code>, or invoke{' '}
          <code className="text-purple-300 font-mono">mcp_import_competitor_config</code> from an authorized MCP copilot for dry-run parsing and Commit-Confirm staging.
        </Callout>
      </section>
    </div>
  );
}
