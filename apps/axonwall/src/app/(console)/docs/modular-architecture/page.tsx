import React from 'react';
import Link from 'next/link';
import { Database, HardDrive, Layers, FolderKanban, Camera, Cpu, ArrowRightLeft, ShieldCheck, Zap, Server, ShieldAlert, Terminal } from 'lucide-react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'Modular Appliance Architecture: 5 Core Roles & 18 Plugins | Axonwall Documentation',
  description:
    'Comprehensive documentation for Axonwall v0.14.1 modular core roles (core-firewall, core-nas, core-k3s, core-virt, core-vigilante), 18 built-in systemd sandboxed extension plugins, SHA-256 bundled binary provisioning, and Minimal edition on-demand installation.',
};

export default function ModularArchitectureDocPage() {
  return (
    <div className="space-y-12">
      {/* Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Core Appliance System Architecture • v0.14.1
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          Modular Core Roles: Firewall, ZFS NAS, K3s, Hypervisor &amp; Vigilante SOC
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Axonwall is a hyper-converged, role-modular operating system governed by <strong>5 Core Roles</strong> and{' '}
          <strong>18 built-in sandboxed extension plugins</strong> (23 total plugins with SHA-256-verified bundled binary archives and on-demand installation on <code className="text-amber-300 font-mono">minimal</code> hosts). Disable <code className="text-emerald-400 font-mono">core-firewall</code> to run as a dedicated Host-Mode ZFS NAS or KVM hypervisor, run as a wire-speed Next-Gen Firewall, or converge all five roles on high-availability bare-metal clusters.
        </p>
      </div>

      {/* Role Comparison Table */}
      <section className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Layers className="w-6 h-6 text-emerald-400" /> Feature & Architecture Comparison: Axonwall Converged Appliance
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Traditional homelab and enterprise infrastructure forced organizations to deploy separate physical appliances or complex nested hypervisors for firewalls, storage, and container runtimes. Axonwall unifies them with native Linux kernel performance, atomic commit-confirm rollback, and zero-drop HA replication.
        </p>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border border-slate-800 rounded-xl overflow-hidden">
            <thead className="bg-slate-900 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="p-3">Capability / Subsystem</th>
                <th className="p-3">Axonwall Converged OS</th>
                <th className="p-3">Dedicated Storage Appliances</th>
                <th className="p-3">Legacy Firewalls</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              <tr className="hover:bg-slate-900/30">
                <td className="p-3 font-semibold text-white">Core Firewall Engine</td>
                <td className="p-3 text-emerald-400 font-medium">Modular plugin (<code className="text-emerald-300">core-firewall</code>), Linux multi-core nftables + Flowtable HW offload</td>
                <td className="p-3 text-slate-400">Basic iptables/docker bridges; no NGFW or stateful routing</td>
                <td className="p-3 text-slate-300">Monolithic FreeBSD pf (single-lock bottleneck on 10G+)</td>
              </tr>
              <tr className="hover:bg-slate-900/30">
                <td className="p-3 font-semibold text-white">Host-Mode Operation</td>
                <td className="p-3 text-emerald-400 font-medium">Yes: Disable firewall to run pure ZFS NAS / K3s host</td>
                <td className="p-3 text-slate-300">Default storage host mode only</td>
                <td className="p-3 text-rose-400">No (firewall is mandatory and cannot be disabled)</td>
              </tr>
              <tr className="hover:bg-slate-900/30">
                <td className="p-3 font-semibold text-white">Storage Subsystem</td>
                <td className="p-3 text-emerald-400 font-medium">Native OpenZFS (Stripe, Mirror, RAID-Z1/Z2/Z3, dRAID) + VSS Shadow Copies</td>
                <td className="p-3 text-emerald-400 font-medium">Native OpenZFS (ZFS pool manager)</td>
                <td className="p-3 text-rose-400">Root ZFS boot only; no NAS file sharing or RAID management</td>
              </tr>
              <tr className="hover:bg-slate-900/30">
                <td className="p-3 font-semibold text-white">Kubernetes Engine</td>
                <td className="p-3 text-emerald-400 font-medium">K3s + OpenEBS distributed CSI (ZFS-LocalPV & Mayastor NVMe-oF)</td>
                <td className="p-3 text-amber-400">Deprecated k3s in legacy storage OS (migrated to standard Docker Engine)</td>
                <td className="p-3 text-rose-400">None</td>
              </tr>
              <tr className="hover:bg-slate-900/30">
                <td className="p-3 font-semibold text-white">2-Node True HA</td>
                <td className="p-3 text-emerald-400 font-medium">Full state sync: VRRP, conntrackd, SQLite DBs, ZFS snapshots & K3s token auto-join</td>
                <td className="p-3 text-slate-400">Dual-controller SAS hardware only; no 2-node commodity HA</td>
                <td className="p-3 text-slate-400">CARP + XMLRPC config sync; no file or container replication</td>
              </tr>
              <tr className="hover:bg-slate-900/30">
                <td className="p-3 font-semibold text-white">Hypervisor &amp; Cyber SOC</td>
                <td className="p-3 text-emerald-400 font-medium">Native KVM/QEMU + LXC + VFIO (<code className="text-emerald-300">core-virt</code>) &amp; Autonomous SOC (<code className="text-emerald-300">core-vigilante</code>)</td>
                <td className="p-3 text-slate-400">Basic VM plugin without NGFW micro-segmentation or SOC</td>
                <td className="p-3 text-rose-400">None</td>
              </tr>
              <tr className="hover:bg-slate-900/30">
                <td className="p-3 font-semibold text-white">Firmware Upgrades</td>
                <td className="p-3 text-emerald-400 font-medium">A/B Dual-Root partitions or ZFSBootMenu Boot Environments with watchdog</td>
                <td className="p-3 text-slate-300">GRUB boot environment snapshots</td>
                <td className="p-3 text-amber-400">In-place package upgrade (high brick risk on power loss)</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* Core Role Plugins */}
      <section id="core-roles" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Cpu className="w-6 h-6 text-emerald-400" /> The 5 Core Appliance Roles (CoreCapabilitiesSchema)
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Axonwall encapsulates its foundational subsystem roles into five schema-governed capabilities under{' '}
          <code className="text-emerald-400 font-mono">capabilities:</code> in <code className="text-emerald-400 font-mono">/etc/axonwall/system.yaml</code>:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          <div className="p-6 rounded-2xl bg-slate-900 border border-emerald-500/30 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5 font-bold text-white text-base">
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
                <span>core-firewall</span>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-500/30">DEFAULT ON</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Schema key: <code className="text-emerald-300 font-mono">firewallEnabled: true</code>. Multi-core line-rate <code className="text-slate-200 font-mono">nftables</code> packet filtering, Dual-Stack IPv4/IPv6 + QinQ VLAN eBPF XDP fast-drop, stateful NAT, Suricata 7+ IPS, CrowdSec, GeoIP sets, Unbound DNS RPZ, and FRR BGP/OSPF multi-WAN routing.
            </p>
            <div className="pt-2 text-[11px] font-mono text-slate-500">
              When toggled off: Compiles an atomic Host-Mode ruleset permitting management, SMB/NFS/iSCSI, KVM bridges, and K3s node traffic without router forwarding.
            </div>
          </div>

          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5 font-bold text-white text-base">
                <Database className="w-5 h-5 text-emerald-400" />
                <span>core-nas</span>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">OPT-IN</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Schema key: <code className="text-emerald-300 font-mono">nasEnabled: true</code>. Enterprise OpenZFS pool &amp; dataset orchestration (<code className="text-slate-200 font-mono">/etc/axonwall/storage.yaml</code>): SLOG/L2ARC/hot-spare tiering, SPL kstat ARC/L2ARC/ZIL telemetry, POSIX ACLs, Samba SMB3 with VSS Shadow Copies, NFSv4, iSCSI targets, and SeaweedFS S3 Object-Lock Vault.
            </p>
            <div className="pt-2 text-[11px] font-mono text-slate-500">
              HA Failover: Incremental ZFS send/recv streams with automatic VRRP MASTER promotion.
            </div>
          </div>

          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5 font-bold text-white text-base">
                <Cpu className="w-5 h-5 text-emerald-400" />
                <span>core-k3s</span>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">OPT-IN</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Schema key: <code className="text-emerald-300 font-mono">k3sEnabled: true</code>. Lightweight Kubernetes (<code className="text-slate-200 font-mono">/etc/axonwall/k3s.yaml</code>) with bundled <code className="text-slate-200 font-mono">k3s</code> &amp; <code className="text-slate-200 font-mono">k9s</code> binaries, WireGuard flannel or Cilium eBPF mesh, embedded-etcd HA auto-join over mTLS, Linux 6.9+ <code className="text-slate-200 font-mono">UserNamespacesSupport</code> + <code className="text-slate-200 font-mono">BPF_TOKEN</code> profiles, and OpenEBS ZFS-LocalPV &amp; Mayastor NVMe-oF storage classes.
            </p>
            <div className="pt-2 text-[11px] font-mono text-slate-500">
              Kubeconfig &amp; UI: Synced via <code className="text-slate-300">axonwall-kubeconfig --vip</code> • Browser Explorer at <code className="text-slate-300">/k3s/explorer</code>
            </div>
          </div>

          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5 font-bold text-white text-base">
                <Server className="w-5 h-5 text-emerald-400" />
                <span>core-virt</span>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">OPT-IN</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Schema key: <code className="text-emerald-300 font-mono">virtEnabled: true</code>. Native Type-1 Linux hypervisor (<code className="text-slate-200 font-mono">/etc/axonwall/virt.yaml</code>) managing QEMU/KVM virtual machines backed by ZFS zvols, unprivileged LXC containers with Linux 6.9+ <code className="text-slate-200 font-mono">BPF_TOKEN</code> delegation, IOMMU PCIe/GPU VFIO passthrough, HTML5 noVNC consoles, and Hosted Virtual Edge UKI micro-VMs.
            </p>
            <div className="pt-2 text-[11px] font-mono text-slate-500">
              Docs: <Link href="/docs/kvm-lxc-hypervisor" className="text-emerald-400 hover:underline">/docs/kvm-lxc-hypervisor</Link>
            </div>
          </div>

          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5 font-bold text-white text-base">
                <ShieldAlert className="w-5 h-5 text-emerald-400" />
                <span>core-vigilante</span>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950/60 text-amber-300 border border-amber-500/30">REQUIRES core-k3s</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Schema key: <code className="text-emerald-300 font-mono">vigilanteEnabled: true</code> (requires <code className="text-slate-200 font-mono">k3sEnabled: true</code>). Deploys the Vigilante Autonomous Cyber Operations suite (<code className="text-slate-200 font-mono">/etc/axonwall/vigilante.yaml</code>): BattleStation triage, Attack Graph engine, Cyber Deception honeypots, Purple Team emulation, and SOAR playbooks.
            </p>
            <div className="pt-2 text-[11px] font-mono text-slate-500">
              Docs: <Link href="/docs/vigilante-cyber-ops" className="text-emerald-400 hover:underline">/docs/vigilante-cyber-ops</Link>
            </div>
          </div>
        </div>
      </section>

      {/* 18 Built-in Extension Plugins */}
      <section id="extension-plugins" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Zap className="w-6 h-6 text-emerald-400" /> 18 Built-In Extension Plugins &amp; Bundled Binaries
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Beyond the 5 Core Roles, Axonwall includes <strong>18 first-party extension plugins</strong> managed declaratively in{' '}
          <code className="text-emerald-400 font-mono">/etc/axonwall/system.yaml</code> or imperatively via{' '}
          <code className="text-emerald-400 font-mono">axonwallctl plugin</code>. Three workstation &amp; host-security plugins ship enabled out of the box (unless provisioned with the <code className="text-amber-300 font-mono">minimal</code> edition), while fifteen specialized network, VPN, AI, editor, and SecOps plugins remain opt-in to keep the default attack surface minimal.
        </p>

        <div className="p-4 rounded-xl bg-slate-900/90 border border-emerald-500/25 text-xs text-slate-300 leading-relaxed space-y-1.5">
          <div className="font-bold text-emerald-300">SHA-256 Bundled Binary Supply Chain &amp; On-Demand Provisioning</div>
          <p>
            Plugins such as <code className="font-mono text-slate-200">core-k3s</code> (<code className="font-mono">k3s</code>, <code className="font-mono">k9s</code>), <code className="font-mono text-slate-200">cli-workstation</code> (<code className="font-mono">vim</code>, <code className="font-mono">neovim</code>), and <code className="font-mono text-slate-200">cli-emacs</code> (bundled Debian Emacs shared with <code className="font-mono">cli-emacs-doom</code> / <code className="font-mono">cli-emacs-spacemacs</code>) verify pinned SHA-256 archives before fail-closed extraction into per-plugin <code className="font-mono text-slate-200">bin/</code> directories, wired automatically into interactive shell <code className="font-mono text-slate-200">PATH</code> snippets and installable on demand from <code className="font-mono text-amber-300">/system/plugins</code>.
          </p>
        </div>

        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full text-left text-xs border-collapse">
            <thead className="bg-slate-900/90 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="p-3">Plugin ID</th>
                <th className="p-3">Default State</th>
                <th className="p-3">Domain YAML</th>
                <th className="p-3">Subsystem Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              <tr>
                <td className="p-2.5 font-mono text-emerald-400 font-semibold">cli-workstation</td>
                <td className="p-2.5 text-emerald-400 font-semibold">Enabled</td>
                <td className="p-2.5 font-mono text-slate-400">system.yaml</td>
                <td className="p-2.5">Bundled <code className="font-mono">vim</code> &amp; <code className="font-mono">neovim</code> Super Configurator (<code className="font-mono">axonwall-config</code>), Oh My Zsh + Starship shell, Tmux, <code className="font-mono">kubectl</code> &amp; <code className="font-mono">helm</code> v3</td>
              </tr>
              <tr>
                <td className="p-2.5 font-mono text-emerald-400 font-semibold">host-malware-rootkit</td>
                <td className="p-2.5 text-emerald-400 font-semibold">Enabled</td>
                <td className="p-2.5 font-mono text-slate-400">security.yaml</td>
                <td className="p-2.5">Ghost-in-the-Ring 8-scanner host defense + 5-hook CO-RE BPF-LSM Ring-0 &amp; <code className="font-mono">BPF_TOKEN</code> mediator (<code className="font-mono">hostDefense:</code>)</td>
              </tr>
              <tr>
                <td className="p-2.5 font-mono text-emerald-400 font-semibold">coroot-ebpf-apm</td>
                <td className="p-2.5 text-emerald-400 font-semibold">Enabled</td>
                <td className="p-2.5 font-mono text-slate-400">system.yaml</td>
                <td className="p-2.5">Zero-instrumentation Ring-0 eBPF service map, TLS uprobes, 99 Hz FlameGraphs, automated RCA, and OpenZFS ARC/ZIL correlation (<code className="font-mono">observability.ebpfApm</code>)</td>
              </tr>
              <tr>
                <td className="p-2.5 font-mono text-cyan-400 font-semibold">ebpf-threat-harvester</td>
                <td className="p-2.5 text-slate-400">Opt-In</td>
                <td className="p-2.5 font-mono text-slate-400">security.yaml</td>
                <td className="p-2.5">Axonwall Blackbox Ring-0 TCX/tracepoint/uprobe flight recorder &amp; Dual-Track SFT/RLVR JSONL + Apache Parquet Threat-LLM dataset harvester (<code className="font-mono">threatHarvester:</code>)</td>
              </tr>
              <tr>
                <td className="p-2.5 font-mono text-sky-400 font-semibold">rosenpass</td>
                <td className="p-2.5 text-slate-400">Opt-In</td>
                <td className="p-2.5 font-mono text-slate-400">vpn.yaml</td>
                <td className="p-2.5">Post-Quantum Dual-KEM VPN (Classic McEliece 460896 + ML-KEM-512 / Kyber-512) 120s WireGuard PSK rotation</td>
              </tr>
              <tr>
                <td className="p-2.5 font-mono text-purple-400 font-semibold">eluvix</td>
                <td className="p-2.5 text-slate-400">Opt-In</td>
                <td className="p-2.5 font-mono text-slate-400">system.yaml</td>
                <td className="p-2.5">Sovereign AI Router (:3588 / Switchyard :8080), PrivacyGuard DLP, PromptGuard, and 8 agent harnesses (<code className="font-mono">eluvix:</code>)</td>
              </tr>
              <tr>
                <td className="p-2.5 font-mono text-sky-400 font-semibold">vigilant-octo-waffle</td>
                <td className="p-2.5 text-slate-400">Opt-In</td>
                <td className="p-2.5 font-mono text-slate-400">k3s.yaml</td>
                <td className="p-2.5">Turnkey K3s DevSecOps &amp; GitOps platform (Argo CD / Flux, Gitea, Vault, Wazuh, Tetragon) under <code className="font-mono">vow:</code></td>
              </tr>
              <tr>
                <td className="p-2.5 font-mono text-sky-400 font-semibold">headscale</td>
                <td className="p-2.5 text-slate-400">Opt-In</td>
                <td className="p-2.5 font-mono text-slate-400">vpn.yaml</td>
                <td className="p-2.5">Self-hosted sovereign Tailscale coordination plane with embedded DERP relay and OpenLDAP OIDC integration</td>
              </tr>
              <tr>
                <td className="p-2.5 font-mono text-sky-400 font-semibold">tailscale</td>
                <td className="p-2.5 text-slate-400">Opt-In</td>
                <td className="p-2.5 font-mono text-slate-400">vpn.yaml</td>
                <td className="p-2.5">Mesh VPN client/subnet-router agent joining either sovereign Headscale or Tailscale SaaS tailnets</td>
              </tr>
              <tr>
                <td className="p-2.5 font-mono text-sky-400 font-semibold">haproxy</td>
                <td className="p-2.5 text-slate-400">Opt-In</td>
                <td className="p-2.5 font-mono text-slate-400">services.yaml</td>
                <td className="p-2.5">High-performance L4/L7 reverse proxy, TLS/SNI termination, ACME automation, and health-checked backend pools</td>
              </tr>
              <tr>
                <td className="p-2.5 font-mono text-sky-400 font-semibold">freeradius</td>
                <td className="p-2.5 text-slate-400">Opt-In</td>
                <td className="p-2.5 font-mono text-slate-400">services.yaml</td>
                <td className="p-2.5">802.1X WPA2/WPA3-Enterprise EAP-TLS / PEAP authentication backed by embedded OpenLDAP</td>
              </tr>
              <tr>
                <td className="p-2.5 font-mono text-sky-400 font-semibold">netbox</td>
                <td className="p-2.5 text-slate-400">Opt-In</td>
                <td className="p-2.5 font-mono text-slate-400">services.yaml</td>
                <td className="p-2.5">NetBox v4 DCIM &amp; IPAM Source of Truth deployed in K3s (<code className="font-mono">core-k3s</code>) with OpenLDAP SSO (<code className="font-mono">svc-netbox</code>) and idempotent Axonwall inventory sync</td>
              </tr>
              <tr>
                <td className="p-2.5 font-mono text-sky-400 font-semibold">librenms</td>
                <td className="p-2.5 text-slate-400">Opt-In</td>
                <td className="p-2.5 font-mono text-slate-400">services.yaml</td>
                <td className="p-2.5">LibreNMS SNMPv2c/v3, LLDP/CDP/FDB discovery, optical DOM &amp; alert webhook hub (<code className="font-mono">core-k3s</code> or external) with OpenLDAP SSO (<code className="font-mono">svc-librenms</code>) and NetBox Triad sync</td>
              </tr>
              <tr>
                <td className="p-2.5 font-mono text-sky-400 font-semibold">topology-studio</td>
                <td className="p-2.5 text-slate-400">Opt-In</td>
                <td className="p-2.5 font-mono text-slate-400">topology.yaml</td>
                <td className="p-2.5">Interactive <code className="font-mono">@xyflow/react</code> multi-host/WAN/K3s/cable fabric studio with strict Green/Yellow/Red health probes, WAN-excluded <code className="font-mono">lldpd</code>, phased transactional apply &amp; NetBox/LibreNMS Triad sync</td>
              </tr>
              <tr>
                <td className="p-2.5 font-mono text-sky-400 font-semibold">snmp</td>
                <td className="p-2.5 text-slate-400">Opt-In</td>
                <td className="p-2.5 font-mono text-slate-400">system.yaml</td>
                <td className="p-2.5">SNMPv2c / SNMPv3 USM encrypted polling &amp; trap daemon (<code className="font-mono">snmpd</code>) exposing IF-MIB and HOST-RESOURCES-MIB</td>
              </tr>
              <tr>
                <td className="p-2.5 font-mono text-sky-400 font-semibold">nut-ups</td>
                <td className="p-2.5 text-slate-400">Opt-In</td>
                <td className="p-2.5 font-mono text-slate-400">system.yaml</td>
                <td className="p-2.5">Network UPS Tools (<code className="font-mono">ups:</code>) USB/SNMP battery telemetry and graceful ZFS/KVM low-battery shutdown</td>
              </tr>
              <tr>
                <td className="p-2.5 font-mono text-sky-400 font-semibold">ntopng</td>
                <td className="p-2.5 text-slate-400">Opt-In</td>
                <td className="p-2.5 font-mono text-slate-400">system.yaml</td>
                <td className="p-2.5">Deep packet L7 application DPI traffic classification and historical flow analytics</td>
              </tr>
              <tr>
                <td className="p-2.5 font-mono text-sky-400 font-semibold">cli-diagnostics-nastymap</td>
                <td className="p-2.5 text-slate-400">Opt-In</td>
                <td className="p-2.5 font-mono text-slate-400">system.yaml</td>
                <td className="p-2.5">Interactive <code className="font-mono">axonwall-tui --nastymap</code> ASCII packet-path &amp; rule-trace topology simulator plus hardware diagnostics</td>
              </tr>
              <tr>
                <td className="p-2.5 font-mono text-sky-400 font-semibold">cli-emacs</td>
                <td className="p-2.5 text-slate-400">Opt-In</td>
                <td className="p-2.5 font-mono text-slate-400">system.yaml</td>
                <td className="p-2.5">Bundled GNU Emacs runtime (<code className="font-mono">emacs</code>) staged into isolated per-plugin <code className="font-mono">bin/</code> with interactive shell <code className="font-mono">PATH</code> snippet</td>
              </tr>
              <tr>
                <td className="p-2.5 font-mono text-sky-400 font-semibold">cli-emacs-doom</td>
                <td className="p-2.5 text-slate-400">Opt-In</td>
                <td className="p-2.5 font-mono text-slate-400">system.yaml</td>
                <td className="p-2.5">Doom Emacs workstation starter sharing the bundled <code className="font-mono">cli-emacs</code> runtime</td>
              </tr>
              <tr>
                <td className="p-2.5 font-mono text-sky-400 font-semibold">cli-emacs-spacemacs</td>
                <td className="p-2.5 text-slate-400">Opt-In</td>
                <td className="p-2.5 font-mono text-slate-400">system.yaml</td>
                <td className="p-2.5">Spacemacs configuration starter sharing the bundled <code className="font-mono">cli-emacs</code> runtime</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* Code Example */}
      <section id="declarative-config" className="space-y-4 pt-6 border-t border-slate-800/80">
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <Terminal className="w-5 h-5 text-emerald-400" /> Managing Roles &amp; Plugins via YAML and CLI
        </h2>
        <p className="text-xs text-slate-400 leading-relaxed">
          Configure Core Roles and extension plugins declaratively in <code className="text-emerald-400 font-mono">/etc/axonwall/system.yaml</code> (with domain-specific settings in <code className="text-slate-200 font-mono">storage.yaml</code>, <code className="text-slate-200 font-mono">k3s.yaml</code>, <code className="text-slate-200 font-mono">virt.yaml</code>, and <code className="text-slate-200 font-mono">vigilante.yaml</code>), or manage plugins directly from the CLI:
        </p>

        <CodeBlock
          title="/etc/axonwall/system.yaml"
          language="yaml"
          code={`version: 1
capabilities:
  firewallEnabled: true
  nasEnabled: true
  k3sEnabled: true
  virtEnabled: true
  vigilanteEnabled: true

plugins:
  - id: cli-workstation
    enabled: true
  - id: host-malware-rootkit
    enabled: true
  - id: coroot-ebpf-apm
    enabled: true
  - id: rosenpass
    enabled: true
  - id: eluvix
    enabled: true
  - id: vigilant-octo-waffle
    enabled: true`}
        />

        <CodeBlock
          title="CLI Plugin Lifecycle Management (axonwallctl plugin)"
          language="bash"
          code={`# List all 5 Core Roles & 18 extension plugins with live systemd & binary state
axonwallctl plugin list

# Enable or disable built-in plugins (updates /etc/axonwall/system.yaml & reconciles)
sudo axonwallctl plugin enable rosenpass
sudo axonwallctl plugin enable eluvix
sudo axonwallctl plugin disable snmp

# Install, remove, or re-sync plugin packages and systemd sandboxes
sudo axonwallctl plugin install vigilant-octo-waffle
sudo axonwallctl plugin remove ntopng
sudo axonwallctl plugin re-sync host-malware-rootkit`}
        />
      </section>
    </div>
  );
}
