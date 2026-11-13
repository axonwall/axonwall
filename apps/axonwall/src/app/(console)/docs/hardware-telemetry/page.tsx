import React from 'react';
import Link from 'next/link';
import { Terminal, Cpu, Gauge, Zap, CheckCircle2, AlertOctagon } from 'lucide-react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'Hardware Telemetry, Optical DOM & Console Command Runner | Axonwall Documentation',
  description:
    'Comprehensive hardware telemetry and shell access documentation for Axonwall v0.11.68: Linux HWMON chassis sensor telemetry, SFP+/QSFP optical DOM transceiver monitoring, RBAC Console Command Runner, KVM noVNC consoles, and SSH/serial TUI.',
};

export default function HardwareTelemetryDocPage() {
  return (
    <div className="space-y-12">
      {/* Page Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Hardware &amp; Management • v0.11.68
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          Hardware Telemetry, Optical DOM &amp; Shell Access
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Monitor physical appliance health and diagnose fiber link degradation. Axonwall aggregates Linux <code className="text-emerald-400 font-mono">hwmon</code> chassis sensors, <code className="text-white font-mono">SFP+/QSFP28 DOM</code> optical transceiver metrics, an RBAC-gated Console Command Runner, KVM HTML5 <code className="text-emerald-400 font-mono">noVNC</code> guest consoles, and full SSH / serial TUI workstations.
        </p>
      </div>

      {/* HWMON Sensors */}
      <section id="hwmon" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Gauge className="w-6 h-6 text-emerald-400" /> Linux HWMON Chassis Sensor Telemetry
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Axonwall autonomously probes <code className="text-slate-200 font-mono">/sys/class/hwmon</code> to collect core thermals, fan speeds, and power supply voltages without requiring external IPMI agents or proprietary drivers:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <span className="font-bold text-emerald-400">Thermal Monitoring</span>
            <p className="text-slate-400">Individual CPU core temperatures (<code className="text-slate-300">coretemp</code> / <code className="text-slate-300">k10temp</code>), motherboard chipset sensors, and NVMe drive thermals.</p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <span className="font-bold text-sky-400">Fan Speed Telemetry</span>
            <p className="text-slate-400">Real-time tachometer readings (RPM), PWM duty cycle percentage, and fan stall warnings.</p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <span className="font-bold text-purple-400">Voltage Rails</span>
            <p className="text-slate-400">Input and output chassis power rails: +12V, +5V, +3.3V, and processor Vcore telemetry.</p>
          </div>
        </div>
      </section>

      {/* SFP+ Optical DOM */}
      <section id="optical-dom" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Cpu className="w-6 h-6 text-emerald-400" /> SFP+ / QSFP Optical Transceiver DOM
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Diagnosing fiber-optic issues usually requires physical optical power meters. Axonwall queries the SFF-8472 / SFF-8436 Digital Optical Monitoring (DOM) registers on SFP+, SFP28, and QSFP28 transceivers via the Linux kernel <code className="text-emerald-400 font-mono">ethtool -m</code> interface:
        </p>

        <CodeBlock
          title="Optical Diagnostics Data (JSON)"
          language="json"
          code={`{
  "interface": "eth2",
  "transceiver": "10GBASE-SR",
  "wavelength_nm": 850,
  "temperature_c": 38.4,
  "voltage_v": 3.28,
  "tx_power_dbm": -2.1,
  "rx_power_dbm": -4.8,
  "tx_bias_current_ma": 6.4,
  "status": "nominal",
  "alarms": []
}`}
        />

        <Callout type="warning" title="Optical Attenuation Warning">
          If physical fiber bending or dirty patch connectors cause RX optical power to drop below the manufacturer sensitivity threshold (typically <code className="text-amber-300 font-mono">-11 dBm</code> for 10G-SR), Axonwall triggers an automated alert before CRC packet loss occurs.
        </Callout>
      </section>

      {/* Console Command Runner & Shell Channels */}
      <section id="web-terminal" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Terminal className="w-6 h-6 text-emerald-400" /> Console Command Runner, SSH Workstation &amp; Guest Consoles
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Rather than exposing an unbounded persistent root WebSocket PTY to browser XSS/session hijacking risks, Axonwall separates browser diagnostics from interactive shell administration across four purpose-built channels:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-emerald-400 text-sm">1. Web Console Command Runner (/system/terminal)</h3>
            <p className="text-slate-400 leading-relaxed">
              Backed by <code className="text-slate-200 font-mono">axonwalld</code> <code className="text-emerald-400 font-mono">/v1/terminal/exec</code> over the authenticated <code className="text-slate-200 font-mono">/run/axonwall/agent-api.sock</code> Unix socket with strict RBAC administrator gating, timeout bounds, and audit logging—ideal for quick browser-based diagnostics.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-sky-400 text-sm">2. Full Interactive SSH Workstation (cli-workstation)</h3>
            <p className="text-slate-400 leading-relaxed">
              Connect via OpenSSH for persistent Tmux sessions, Oh My Zsh + Starship prompts, the 12-domain Neovim Super Configurator (<code className="text-slate-200 font-mono">axonwall-config</code>), and the 11-tab <code className="text-slate-200 font-mono">axonwall-tui</code> cockpit.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-purple-400 text-sm">3. KVM Guest HTML5 noVNC Consoles</h3>
            <p className="text-slate-400 leading-relaxed">
              Virtual machines managed by <code className="text-slate-200 font-mono">core-virt</code> stream interactive graphical and serial guest consoles over <code className="text-emerald-400 font-mono">/v1/virt/console/ws</code> directly into the Web Console&apos;s embedded HTML5 <code className="text-slate-200 font-mono">noVNC</code> viewer.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-amber-400 text-sm">4. Physical VGA &amp; RS-232 Serial Console</h3>
            <p className="text-slate-400 leading-relaxed">
              Out-of-band physical VGA and <code className="text-slate-200 font-mono">ttyS0</code> (115200 8N1) interfaces launch <code className="text-emerald-400 font-mono">axonwall-console</code> for emergency interface assignment, password recovery, and Commit-Confirm inspection.
            </p>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2 text-xs">
          <span className="font-bold text-white">Common Diagnostic Commands:</span>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-slate-300 font-mono">
            <div className="p-2 rounded bg-black/40"><code className="text-emerald-400">nft list table inet axonwall</code> - Inspect live kernel filter</div>
            <div className="p-2 rounded bg-black/40"><code className="text-emerald-400">conntrack -L</code> - Dump active connection states</div>
            <div className="p-2 rounded bg-black/40"><code className="text-emerald-400">ethtool -m eth2</code> - Raw optical transceiver DOM</div>
            <div className="p-2 rounded bg-black/40"><code className="text-emerald-400">journalctl -u axonwalld -f</code> - Stream daemon logs</div>
          </div>
        </div>

        <Callout type="tip" title="Access Console Command Runner & Sensors">
          Navigate to <code className="text-emerald-300 font-mono">System &gt; Web Shell &amp; Sensors (/system/terminal)</code> in the Web Console to inspect HWMON thermals, SFP+ DOM gauges, and execute RBAC-audited diagnostic commands.
        </Callout>
      </section>
    </div>
  );
}
