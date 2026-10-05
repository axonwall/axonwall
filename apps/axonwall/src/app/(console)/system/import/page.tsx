'use client';

import { useState } from 'react';
import { UploadCloud, CheckCircle2, AlertTriangle, FileText, ArrowRight, ShieldCheck, Play } from 'lucide-react';
import { importOpnsenseConfig, type ImportReport } from '@axonwall/lib/import/opnsense';
import { compileNftables } from '@axonwall/lib/compile/nft';

const SAMPLE_XML_PLACEHOLDER = `<?xml version="1.0"?>
<opnsense version="24.7">
  <system>
    <hostname>opnsense-core</hostname>
    <domain>lab.local</domain>
  </system>
  <interfaces>
    <wan><if>eth0</if><ipaddr>dhcp</ipaddr><descr>WAN</descr></wan>
    <lan><if>eth1</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet><descr>LAN</descr></lan>
  </interfaces>
  <filter>
    <rule>
      <type>pass</type>
      <interface>lan</interface>
      <protocol>tcp</protocol>
      <destination><port>443</port></destination>
      <descr>Allow HTTPS</descr>
    </rule>
  </filter>
</opnsense>`;

export default function ImportPage() {
  const [xmlInput, setXmlInput] = useState(SAMPLE_XML_PLACEHOLDER);
  const [report, setReport] = useState<ImportReport | null>(null);
  const [compiledNft, setCompiledNft] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  function handleImport() {
    setError(null);
    try {
      const res = importOpnsenseConfig(xmlInput);
      setReport(res);
      const { nftScript } = compileNftables(res.state);
      setCompiledNft(nftScript);
    } catch (err: any) {
      setError(err.message);
      setReport(null);
      setCompiledNft(null);
    }
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white">OPNsense Migration Importer</h1>
        <p className="text-sm text-slate-400 mt-1">
          Import existing OPNsense or pfSense <code className="text-emerald-400 font-mono">config.xml</code> files directly into modern Axonwall Linux nftables configurations.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* XML Input Editor */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-sm font-semibold text-white flex items-center gap-2">
              <UploadCloud className="w-4 h-4 text-emerald-400" />
              <span>OPNsense config.xml Input</span>
            </span>
            <button
              type="button"
              onClick={handleImport}
              className="bg-emerald-600 hover:bg-emerald-500 text-white px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Parse & Convert</span>
            </button>
          </div>

          <textarea
            value={xmlInput}
            onChange={(e) => setXmlInput(e.target.value)}
            rows={14}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-emerald-500"
            placeholder="Paste OPNsense or pfSense config.xml here..."
          />

          {error && (
            <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-xs text-red-400 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}
        </div>

        {/* Migration Report */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <span className="text-sm font-semibold text-white flex items-center gap-2">
            <FileText className="w-4 h-4 text-cyan-400" />
            <span>Compatibility & Extraction Summary</span>
          </span>

          {report ? (
            <div className="space-y-4">
              <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg flex items-center gap-2 text-xs text-emerald-300">
                <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
                <span>
                  Successfully translated OPNsense {report.version} configuration into Axonwall DesiredState!
                </span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs font-mono">
                <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                  <span className="text-slate-400 block font-sans">Interfaces</span>
                  <span className="text-base font-bold text-white">{report.interfacesCount}</span>
                </div>
                <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                  <span className="text-slate-400 block font-sans">Aliases</span>
                  <span className="text-base font-bold text-white">{report.aliasesCount}</span>
                </div>
                <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                  <span className="text-slate-400 block font-sans">Filter Rules</span>
                  <span className="text-base font-bold text-emerald-400">{report.rulesCount}</span>
                </div>
                <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                  <span className="text-slate-400 block font-sans">NAT Rules</span>
                  <span className="text-base font-bold text-white">{report.natRulesCount}</span>
                </div>
                <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                  <span className="text-slate-400 block font-sans">DHCP Pools</span>
                  <span className="text-base font-bold text-white">{report.dhcpSubnetsCount}</span>
                </div>
                <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                  <span className="text-slate-400 block font-sans">DNS Overrides</span>
                  <span className="text-base font-bold text-white">{report.dnsOverridesCount}</span>
                </div>
              </div>
            </div>
          ) : (
            <div className="h-64 flex flex-col items-center justify-center text-slate-500 text-xs">
              <ShieldCheck className="w-12 h-12 text-slate-700 mb-2" />
              <span>Click "Parse & Convert" to analyze configuration compatibility.</span>
            </div>
          )}
        </div>
      </div>

      {/* Real-time Generated nftables Preview */}
      {compiledNft && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-sm font-semibold text-white flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>Converted Linux nftables Ruleset Preview</span>
            </span>
            <span className="text-xs text-slate-400 font-mono">pf → nftables translation</span>
          </div>
          <pre className="bg-slate-950 border border-slate-800/80 rounded-lg p-4 font-mono text-xs text-slate-300 overflow-x-auto max-h-96 leading-relaxed">
            {compiledNft}
          </pre>
        </div>
      )}
    </div>
  );
}
