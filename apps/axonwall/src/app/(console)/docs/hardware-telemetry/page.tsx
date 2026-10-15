import React from 'react';
import Link from 'next/link';
import { Terminal, Cpu, Gauge, Zap, CheckCircle2, AlertOctagon } from 'lucide-react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'Hardware Telemetry & Web Shell | Axonwall Documentation',
  description:
    'Comprehensive hardware telemetry and web terminal documentation for Axonwall: Linux HWMON sensor telemetry, SFP+/QSFP optical DOM transceiver monitoring, and root PTY shell.',
};

export default function HardwareTelemetryDocPage() {
  return (
    <div className="space-y-12">
      {/* Page Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Hardware & Management
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          Hardware Telemetry & Web Shell
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Monitor physical appliance health and diagnose fiber link degradation. Axonwall aggregates Linux <code className="text-emerald-400 font-mono">hwmon</code> chassis sensors, <code className="text-white font-mono">SFP+ DOM</code> optical metrics, and an integrated root web pseudo-terminal (PTY).
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

      {/* Web PTY Shell */}
      <section id="web-terminal" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Terminal className="w-6 h-6 text-emerald-400" /> Integrated PTY Web Terminal
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          When deep system administration is needed, administrators can open a full-featured pseudo-terminal (PTY) directly inside the web browser without configuring external SSH key pairs or port forwards.
        </p>

        <div className="space-y-4">
          <h3 className="text-base font-semibold text-white">PTY Architecture</h3>
          <p className="text-xs text-slate-300 leading-relaxed">
            The privileged Go daemon allocates a Linux pseudo-terminal using <code className="text-slate-200">creack/pty</code>, spawning a dedicated bash shell with full ANSI color support, tab completion, and window resizing (<code className="text-slate-200">TIOCSWINSZ</code>).
          </p>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2 text-xs">
            <span className="font-bold text-white">Common Diagnostic Commands:</span>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-slate-300 font-mono">
              <div className="p-2 rounded bg-black/40"><code className="text-emerald-400">nft list ruleset</code> - Inspect live kernel filter</div>
              <div className="p-2 rounded bg-black/40"><code className="text-emerald-400">conntrack -L</code> - Dump active connection states</div>
              <div className="p-2 rounded bg-black/40"><code className="text-emerald-400">ethtool -m eth2</code> - Raw optical transceiver DOM</div>
              <div className="p-2 rounded bg-black/40"><code className="text-emerald-400">journalctl -u axonwalld -f</code> - Stream daemon logs</div>
            </div>
          </div>
        </div>

        <Callout type="tip" title="Access Web Terminal">
          Navigate to <code className="text-emerald-300 font-mono">System &gt; Web Shell &amp; Sensors (/system/terminal)</code> in the web console to launch the interactive terminal session.
        </Callout>
      </section>
    </div>
  );
}
