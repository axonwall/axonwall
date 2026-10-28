import React from 'react';
import Link from 'next/link';
import { Terminal, Cpu, Zap, Layers, Command, CheckCircle2 } from 'lucide-react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'Neovim Super Configurator TUI, NastyMap & ZSH Workstation | Axonwall Documentation',
  description:
    'Configure every Axonwall subsystem from SSH or serial console using the Neovim Super Configurator TUI (axonwall-config) with native Vim motions, the NastyMap topology simulator, and the pre-configured ZSH power-user shell.',
};

export default function CliSuperConfiguratorDocPage() {
  return (
    <div className="space-y-12">
      {/* Page Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Terminal UX • Neovim Lua Form TUI &amp; ZSH Workstation
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          Neovim Super Configurator, NastyMap &amp; ZSH Shell
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Axonwall treats the command line as a first-class cockpit. Whether you connect over SSH, a serial console, or
          the embedded Web PTY, you get a hyperfocused <strong>Neovim Super Configurator TUI</strong> (
          <code className="text-emerald-400 font-mono">axonwall-config</code>), the interactive{' '}
          <strong>NastyMap Topology &amp; Packet Simulator</strong> (<code className="text-white font-mono">axonwallctl tui</code>),
          and a pre-tuned <strong>Oh My Zsh + Starship</strong> environment.
        </p>
      </div>

      {/* Section 1: Neovim Super Configurator */}
      <section id="neovim-super-configurator" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Terminal className="w-6 h-6 text-emerald-400" /> 1. Neovim Super Configurator (<code className="font-mono text-emerald-400">axonwall-config</code>)
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Editing raw YAML files under pressure can lead to indentation errors, while traditional <code className="text-white font-mono">whiptail</code>{' '}
          or <code className="text-white font-mono">dialog</code> menus strip away keyboard speed.{' '}
          <code className="text-emerald-400 font-mono">axonwall-config</code> uses a custom Neovim Lua runtime (
          <code className="text-white font-mono">/usr/share/axonwall/nvim/init.lua</code>) that renders a clean,
          two-pane form interface with virtual-text badges while keeping full native Vim motions (
          <code className="text-emerald-300 font-mono">hjkl</code>, <code className="text-emerald-300 font-mono">w</code>/
          <code className="text-emerald-300 font-mono">b</code>, <code className="text-emerald-300 font-mono">ciw</code>,{' '}
          <code className="text-emerald-300 font-mono">/search</code>) inside every editable field.
        </p>

        <CodeBlock
          title="Neovim Super Configurator TUI Layout (axonwall-config)"
          language="text"
          code={`+--------------------------+----------------------------------------------------------+
|  AXONWALL DOMAINS        |  [6] High Availability (Keepalived VRRP & conntrackd)    |
|                          |  File: /etc/axonwall/ha.yaml                [MODIFIED]   |
|  1. Interfaces & VLANs   |----------------------------------------------------------|
|  2. Firewall Rules       |  > Enable High Availability : [x] true      ( toggle )   |
|  3. NAT & Port Forwards  |    Node Role                : <master>      ( ge enum )  |
|  4. DHCP & Unbound DNS   |    Dedicated Sync Interface : [eth3                ]     |
|  5. WireGuard & PQ-KEM   |    Peer Sync IPv4 Address   : [10.0.99.2           ]     |
| >6. High Availability    |    Primary VRID             : [51                  ]     |
|  7. OpenZFS NAS Storage  |    VRRP Priority (1-254)    : [150                 ]     |
|  8. K3s & OpenEBS        |    mTLS Transport Mode      : <mtls>        ( ge enum )  |
|  9. Vigilant Octo Waffle |    Require Signed Payloads  : [x] true      ( toggle )   |
| 10. Rootkit & Ring-0     |                                                          |
| 11. System Plugins       |  [Tab/S-Tab] Field  [Space] Toggle  [ge] Enum  [gy] YAML |
|                          |  [Ctrl+s] Validate & Apply (60s Commit-Confirm)  [q] Quit|
+--------------------------+----------------------------------------------------------+`}
        />

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">Keybindings &amp; Vim Ergonomics</h3>
            <ul className="space-y-1.5 text-slate-300 list-disc list-inside">
              <li><code className="font-mono text-emerald-400">Tab</code> / <code className="font-mono text-emerald-400">Shift+Tab</code>: Jump directly between form input fields</li>
              <li><code className="font-mono text-emerald-400">Space</code> or <code className="font-mono text-emerald-400">Enter</code>: Toggle boolean checkboxes (<code className="font-mono">[x] true</code> / <code className="font-mono">[ ] false</code>)</li>
              <li><code className="font-mono text-emerald-400">ge</code>: Open floating enum selector popup for constrained fields</li>
              <li><code className="font-mono text-emerald-400">gy</code>: Preview the live-compiled YAML buffer in a floating window</li>
              <li><code className="font-mono text-emerald-400">Ctrl+s</code>: Validate schema and run <code className="font-mono">axonwallctl apply</code> with Commit-Confirm</li>
            </ul>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">Direct Section Jump Commands</h3>
            <CodeBlock
              title="Open Directly to Any Subsystem"
              language="bash"
              code={`axonwall-config              # Open interactive 11-domain hub
axonwall-config interfaces   # Physical NICs, VLANs, Bonds, Multi-WAN
axonwall-config firewall     # Stateful nftables rules & zones
axonwall-config wireguard    # WireGuard & Post-Quantum Rosenpass
axonwall-config ha           # 2-Host High Availability & mTLS sync
axonwall-config vow          # Vigilant Octo Waffle K3s GitOps stack
axonwall-config rootkit      # rkhunter & Ghost-in-the-Ring Hunter`}
            />
          </div>
        </div>
      </section>

      {/* Section 2: NastyMap TUI */}
      <section id="nastymap-tui" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Layers className="w-6 h-6 text-emerald-400" /> 2. NastyMap Topology &amp; Live Packet Simulator (<code className="font-mono text-emerald-400">axonwallctl tui</code>)
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Launch <code className="text-emerald-400 font-mono">axonwallctl tui</code> to open the full-screen Ink/React
          terminal dashboard featuring live network topology visualization, a Braille/Unicode GeoIP threat map, a dry-run
          nftables packet simulator, and a GitOps unified diff inspector.
        </p>
      </section>

      {/* Section 3: ZSH Power-User Workstation */}
      <section id="zsh-workstation" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Command className="w-6 h-6 text-emerald-400" /> 3. ZSH Power-User Shell (<code className="font-mono text-emerald-400">cli-workstation</code>)
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Enabled by default on every Axonwall appliance, <code className="text-emerald-400 font-mono">cli-workstation</code>{' '}
          configures <code className="text-white font-mono">zsh</code> with Oh My Zsh, syntax highlighting, autosuggestions,
          a custom <strong>Starship</strong> prompt that displays a flashing red{' '}
          <code className="text-rose-400 font-mono">COMMIT-CONFIRM (60s)</code> badge whenever a rollback timer is
          pending, and complete tab-completions for <code className="text-white font-mono">axonwallctl</code>,{' '}
          <code className="text-white font-mono">axonwall-config</code>, <code className="text-white font-mono">kubectl</code>,{' '}
          <code className="text-white font-mono">helm</code>, <code className="text-white font-mono">zfs</code>,{' '}
          <code className="text-white font-mono">zpool</code>, <code className="text-white font-mono">virsh</code>,{' '}
          <code className="text-white font-mono">nft</code>, and <code className="text-white font-mono">wg</code>.
        </p>
      </section>
    </div>
  );
}
