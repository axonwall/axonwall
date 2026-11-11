import React from 'react';
import { Terminal, Zap, Layers, Command } from 'lucide-react';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'Neovim Super Configurator, axonwall-tui, axonwallctl & ZSH Workstation | Axonwall Documentation',
  description:
    'Configure every Axonwall v0.11.64 subsystem from SSH or serial console using the 12-domain Neovim Super Configurator (axonwall-config), standalone 11-tab axonwall-tui + NastyMap simulator, axonwallctl CLI, and ZSH workstation.',
};

export default function CliSuperConfiguratorDocPage() {
  return (
    <div className="space-y-12">
      {/* Page Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Terminal UX • 12-Domain Neovim TUI, axonwall-tui &amp; ZSH Workstation • v0.11.64
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          Neovim Super Configurator, axonwall-tui &amp; CLI Reference
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Axonwall treats the command line as a first-class cockpit. Connect over SSH or serial console to drive the 12-domain <strong>Neovim Super Configurator</strong> (
          <code className="text-emerald-400 font-mono">axonwall-config</code>), the standalone 11-tab{' '}
          <strong>Axonwall TUI &amp; NastyMap Simulator</strong> (<code className="text-emerald-400 font-mono">axonwall-tui</code>), the declarative{' '}
          <code className="text-white font-mono">axonwallctl</code> CLI, and a pre-tuned <strong>Oh My Zsh + Starship</strong> workstation.
        </p>
      </div>

      {/* Section 1: Neovim Super Configurator */}
      <section id="neovim-super-configurator" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Terminal className="w-6 h-6 text-emerald-400" /> 1. Neovim Super Configurator (<code className="font-mono text-emerald-400">axonwall-config</code>) — All 12 YAML Domains
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          <code className="text-emerald-400 font-mono">axonwall-config</code> (also accessible via <code className="text-emerald-400 font-mono">axonwallctl config [domain]</code>) launches an isolated Neovim Lua workspace mapping 1:1 to all <strong>12 canonical YAML domain files</strong> in <code className="text-slate-200 font-mono">/etc/axonwall/</code>, pairing structured multi-pane navigation with live diff and schema drawers:
        </p>

        <CodeBlock
          title="Neovim Super Configurator 12-Domain TUI Layout (axonwall-config)"
          language="text"
          code={`+------------------------+------------------------------------------------------------+
|  12 AXONWALL DOMAINS   |  [8] ha.yaml — High Availability & Fleet Satellites        |
|                        |  Path: /etc/axonwall/ha.yaml                    [MODIFIED] |
|  1. system             |------------------------------------------------------------|
|  2. interfaces         |  ha:                                                       |
|  3. firewall           |    enabled: true                                           |
|  4. routing            |    nodeRole: master                                        |
|  5. services           |    syncInterface: eth3                                     |
|  6. vpn                |    peerAddress: 10.0.99.2                                  |
|  7. security           |    sqliteSync:                                             |
| >8. ha                 |      enabled: true                                         |
|  9. storage            |      transport: mtls                                       |
| 10. k3s                |      requireSignedPayloads: true                           |
| 11. virt               |                                                            |
| 12. vigilante          |  [<Tab>] Switch Pane  [j/k] Domain  [<C-d>] Diff Drawer    |
|                        |  [<C-y>] YAML/Schema  [<C-s>/:AxonSave]  [:AxonApply]      |
+------------------------+------------------------------------------------------------+`}
        />

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">Keybindings, Drawers &amp; Ex Commands</h3>
            <ul className="space-y-1.5 text-slate-300 list-disc list-inside">
              <li><code className="font-mono text-emerald-400">&lt;Tab&gt;</code>: Switch focus between left 12-domain sidebar and active editor pane</li>
              <li><code className="font-mono text-emerald-400">j</code> / <code className="font-mono text-emerald-400">k</code> (in sidebar): Navigate across the 12 canonical YAML domains</li>
              <li><code className="font-mono text-emerald-400">&lt;C-d&gt;</code>: Toggle live structural unified diff drawer against committed state</li>
              <li><code className="font-mono text-emerald-400">&lt;C-y&gt;</code>: Toggle compiled YAML / Zod schema reference drawer</li>
              <li><code className="font-mono text-emerald-400">&lt;C-s&gt;</code> or <code className="font-mono text-emerald-400">:AxonSave</code>: Validate schema and write domain file to <code className="font-mono">/etc/axonwall/*.yaml</code></li>
              <li><code className="font-mono text-emerald-400">:AxonApply</code>: Trigger <code className="font-mono">axonwallctl apply</code> with 120s Commit-Confirm safety</li>
            </ul>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">Direct Jump to Any of the 12 Domains</h3>
            <CodeBlock
              title="Open Directly to Any Canonical YAML Domain"
              language="bash"
              code={`axonwall-config              # Interactive 12-domain workspace
axonwall-config system       # Capabilities, plugins, Eluvix, observability
axonwall-config interfaces   # Physical NICs, VLANs, bridges, bonds, VRFs
axonwall-config firewall     # Aliases, nftables rules, NAT, trafficShaper
axonwall-config routing      # Gateways, multi-WAN groups, static & FRR BGP/OSPF
axonwall-config services     # Kea DHCP, Unbound DNS/RPZ, HAProxy, FreeRADIUS
axonwall-config vpn          # WireGuard, PQ Rosenpass, IPsec, OpenVPN, Headscale
axonwall-config security     # Suricata, CrowdSec, GeoIP, SSO, hostDefense
axonwall-config ha           # 2-Host High Availability & Fleet Edge nodes
axonwall-config storage      # OpenZFS pools, datasets, SMB/NFS/iSCSI, S3 Vault
axonwall-config k3s          # K3s cluster, OpenEBS CSI, Vigilant Octo Waffle
axonwall-config virt         # KVM/QEMU VMs, LXC containers, VFIO, hostedEdge
axonwall-config vigilante    # Vigilante Autonomous SOC & SOAR`}
            />
          </div>
        </div>
      </section>

      {/* Section 2: Standalone axonwall-tui & NastyMap */}
      <section id="nastymap-tui" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Layers className="w-6 h-6 text-emerald-400" /> 2. Standalone 11-Tab TUI &amp; NastyMap Simulator (<code className="font-mono text-emerald-400">axonwall-tui</code>)
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Launch the standalone <code className="text-emerald-400 font-mono">axonwall-tui</code> binary to open Axonwall&apos;s real-time terminal cockpit across <strong>11 top-level tabs</strong>, including the interactive <strong>NastyMap</strong> topology &amp; dry-run packet path simulator:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5 font-mono text-slate-300">
            <div className="font-sans font-bold text-white text-sm mb-2">11 Top-Level Tabs in axonwall-tui</div>
            <p><span className="text-emerald-400">[1]</span> Dashboard &amp; Live Throughput</p>
            <p><span className="text-emerald-400">[2]</span> Interfaces, VLANs &amp; Optical DOM</p>
            <p><span className="text-emerald-400">[3]</span> Firewall Rules &amp; Live Drops</p>
            <p><span className="text-emerald-400">[4]</span> Routing, Gateways &amp; BGP/OSPF</p>
            <p><span className="text-emerald-400">[5]</span> Services &amp; Post-Quantum Rosenpass (<code className="text-amber-300">[g]</code> keygen)</p>
            <p><span className="text-emerald-400">[6]</span> High Availability &amp; Sync Trust</p>
            <p><span className="text-emerald-400">[7]</span> OpenZFS NAS Pools &amp; Snapshots</p>
            <p><span className="text-emerald-400">[8]</span> K3s Pods &amp; KVM/LXC Guests</p>
            <p><span className="text-emerald-400">[9]</span> NastyMap Topology &amp; Packet Simulator</p>
            <p><span className="text-emerald-400">[u]</span> ZFSBootMenu / A-B Boot Slots &amp; Updates</p>
            <p><span className="text-emerald-400">[0]</span> System, Plugins, GitOps &amp; Ops</p>
          </div>

          <div className="space-y-3">
            <CodeBlock
              title="Launching axonwall-tui"
              language="bash"
              code={`# Launch full interactive 11-tab cockpit
axonwall-tui

# Jump directly into Tab [9] NastyMap packet-path & topology simulator
axonwall-tui --nastymap

# Open a specific named tab or enforce read-only NOC observation mode
axonwall-tui --tab firewall
axonwall-tui --readonly`}
            />
          </div>
        </div>
      </section>

      {/* Section 3: axonwallctl CLI Reference */}
      <section id="axonwallctl-reference" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Zap className="w-6 h-6 text-emerald-400" /> 3. Complete <code className="font-mono text-emerald-400">axonwallctl</code> Subcommand Reference
        </h2>
        <CodeBlock
          title="axonwallctl Control-Plane CLI Commands"
          language="bash"
          code={`axonwallctl status                         # Daemon health, boot slot/BE, active roles, pending timer
axonwallctl validate                       # Lint all 12 /etc/axonwall/*.yaml files + nft -c dry-run
axonwallctl diff                           # Structural diff between /etc/axonwall/*.yaml and live state
sudo axonwallctl apply                     # Apply bundle with 120s Commit-Confirm auto-revert timer
sudo axonwallctl apply --no-confirm        # Apply and commit immediately (automation / CI pipelines)
sudo axonwallctl confirm                   # Confirm pending Commit-Confirm transaction before timeout
sudo axonwallctl rollback [revision]       # Roll back to previous or specific GitOps SHA revision
axonwallctl zbm <list|snapshot|clone|activate|delete|delete-snapshot>
sudo axonwallctl update [--apt] [--version <ver>] [--slot <A|B>]
sudo axonwallctl plugin <list|enable|disable|install|remove|re-sync> <id>
axonwallctl kubeconfig [--vip]             # Export local or VRRP VIP-bound K3s ~/.kube/config
axonwallctl ebpf overview [--json]         # Dual-Stack VLAN XDP counters, SYN shield, BPF-LSM & BPF_TOKEN mounts
axonwallctl ebpf tokens [--json]           # Inspect /run/axonwall/bpffs-tokens/<profile> delegation mounts
axonwallctl ebpf xdp-blocks [--json]       # List active IPv4/IPv6 host & LPM CIDR TTL XDP_DROP entries
sudo axonwallctl ebpf xdp-drop <ip|cidr> [--ttl <sec>] [--reason <text>]
sudo axonwallctl ebpf xdp-unblock <ip|cidr>
sudo axonwallctl ebpf syn-limit [pps|off]  # Inspect or set Ring-0 TCP SYN-flood PPS rate limit (>= 100 PPS)
axonwallctl ebpf render-k3s [--profile networking-safe] [--namespace default] [--name <pod>]
axonwallctl nas <status|snapshot|rollback|scrub|trim|checkpoint|unlock|lock> ...
axonwallctl virt <list|start|stop|reboot|snapshot|rollback|clone|migrate|xml> ...
axonwallctl k3s <status|etcd-snapshots|etcd-save|etcd-restore> ...
axonwallctl import <file> [--type auto|pfsense|opnsense|proxmox|truenas|...] [--merge] [--stage] [--apply]
axonwallctl mcp                            # Start stdio Model Context Protocol (MCP) 24-tool security server
axonwallctl cloudinit export --iso -o cidata.iso
axonwallctl config [domain]                # Launch Neovim Super Configurator on optional domain
axonwallctl edit <domain>                  # Edit raw /etc/axonwall/<domain>.yaml with schema check
axonwallctl export [--format json|yaml]    # Export merged DesiredState bundle
axonwallctl completion <zsh|bash|fish>     # Generate shell tab-completion script`}
        />
      </section>

      {/* Section 4: ZSH Power-User Workstation */}
      <section id="zsh-workstation" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Command className="w-6 h-6 text-emerald-400" /> 4. ZSH Power-User Shell (<code className="font-mono text-emerald-400">cli-workstation</code>)
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Enabled by default on every Axonwall appliance, <code className="text-emerald-400 font-mono">cli-workstation</code>{' '}
          configures <code className="text-white font-mono">zsh</code> with Oh My Zsh, syntax highlighting, autosuggestions, Tmux, bundled{' '}
          <code className="text-emerald-400 font-mono">kubectl</code> &amp; <code className="text-emerald-400 font-mono">helm</code> v3, tactical aliases (<code className="text-slate-200 font-mono">ax</code> for <code className="text-slate-200 font-mono">axonwallctl</code>, <code className="text-slate-200 font-mono">axc</code> for <code className="text-slate-200 font-mono">axonwall-config</code>, <code className="text-slate-200 font-mono">axt</code> for <code className="text-slate-200 font-mono">axonwall-tui</code>, <code className="text-slate-200 font-mono">k</code> for <code className="text-slate-200 font-mono">kubectl</code>), a custom <strong>Starship</strong> prompt that displays a flashing red{' '}
          <code className="text-rose-400 font-mono">COMMIT-CONFIRM (120s)</code> badge whenever a rollback timer is
          pending, and complete tab-completions for <code className="text-white font-mono">axonwallctl</code>,{' '}
          <code className="text-white font-mono">axonwall-config</code>, <code className="text-white font-mono">axonwall-tui</code>, <code className="text-white font-mono">kubectl</code>,{' '}
          <code className="text-white font-mono">helm</code>, <code className="text-white font-mono">zfs</code>,{' '}
          <code className="text-white font-mono">zpool</code>, <code className="text-white font-mono">virsh</code>,{' '}
          <code className="text-white font-mono">nft</code>, and <code className="text-white font-mono">wg</code>.
        </p>
      </section>
    </div>
  );
}
