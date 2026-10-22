import React, { useState, useRef } from 'react';
import type { NmapRun } from '../types/nmap';
import { parseNmapXml } from '../parser/nmap-xml-parser';
import { SAMPLE_SCANS } from '../data/sample-scans';
import { Upload, FileCode, CheckCircle, AlertTriangle, Sparkles, FolderOpen, ArrowRight } from 'lucide-react';

export interface ScanUploaderProps {
  onScanLoaded: (scan: NmapRun, label?: string) => void;
  className?: string;
}

export function ScanUploader({ onScanLoaded, className = '' }: ScanUploaderProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [pastedXml, setPastedXml] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'upload' | 'paste' | 'samples'>('samples');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleProcessXml = (xmlString: string, label?: string) => {
    try {
      setError(null);
      const parsed = parseNmapXml(xmlString);
      onScanLoaded(parsed, label);
    } catch (err: any) {
      setError(err.message || 'Failed to parse XML scan.');
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      handleProcessXml(content, file.name);
    };
    reader.readAsText(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      handleProcessXml(content, file.name);
    };
    reader.readAsText(file);
  };

  return (
    <div className={`p-6 rounded-2xl bg-zinc-950/90 border border-zinc-800/80 space-y-5 ${className}`}>
      {/* Navigation tabs */}
      <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
        <div>
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <FileCode size={18} className="text-sky-400" />
            <span>Load Nmap Scan</span>
          </h3>
          <p className="text-xs text-zinc-400 mt-0.5">Choose a preloaded sample scan, upload an XML file, or paste raw XML.</p>
        </div>

        <div className="flex items-center gap-1 bg-zinc-900 p-1 rounded-lg border border-zinc-800 text-xs font-medium">
          <button
            onClick={() => setActiveTab('samples')}
            className={`px-3 py-1 rounded-md transition-colors ${
              activeTab === 'samples'
                ? 'bg-sky-600 text-white shadow'
                : 'text-zinc-400 hover:text-white'
            }`}
          >
            Sample Scans
          </button>
          <button
            onClick={() => setActiveTab('upload')}
            className={`px-3 py-1 rounded-md transition-colors ${
              activeTab === 'upload'
                ? 'bg-sky-600 text-white shadow'
                : 'text-zinc-400 hover:text-white'
            }`}
          >
            Upload File
          </button>
          <button
            onClick={() => setActiveTab('paste')}
            className={`px-3 py-1 rounded-md transition-colors ${
              activeTab === 'paste'
                ? 'bg-sky-600 text-white shadow'
                : 'text-zinc-400 hover:text-white'
            }`}
          >
            Paste XML
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-rose-950/60 border border-rose-800/60 flex items-center gap-2.5 text-xs text-rose-300">
          <AlertTriangle size={16} className="text-rose-400 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* SAMPLES TAB */}
      {activeTab === 'samples' && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
          <div
            onClick={() => handleProcessXml(SAMPLE_SCANS.enterprise.xml, SAMPLE_SCANS.enterprise.name)}
            className="p-4 rounded-xl bg-zinc-900/60 border border-zinc-800 hover:border-sky-500/60 cursor-pointer transition-all hover:bg-zinc-850 group space-y-2"
          >
            <div className="flex items-center justify-between">
              <span className="px-2 py-0.5 rounded bg-sky-950 text-sky-400 text-[10px] font-bold uppercase border border-sky-800/50">
                Enterprise
              </span>
              <Sparkles size={14} className="text-sky-400 group-hover:scale-110 transition-transform" />
            </div>
            <h4 className="text-sm font-semibold text-white group-hover:text-sky-300 transition-colors">
              Enterprise Multi-Subnet
            </h4>
            <p className="text-xs text-zinc-400 leading-relaxed line-clamp-2">
              Corporate network with pfSense firewall, Cisco core switch, Windows DC, Linux servers, macOS, and traceroute hops.
            </p>
          </div>

          <div
            onClick={() => handleProcessXml(SAMPLE_SCANS.global.xml, SAMPLE_SCANS.global.name)}
            className="p-4 rounded-xl bg-zinc-900/60 border border-zinc-800 hover:border-emerald-500/60 cursor-pointer transition-all hover:bg-zinc-850 group space-y-2"
          >
            <div className="flex items-center justify-between">
              <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 text-[10px] font-bold uppercase border border-emerald-800/50">
                Global GeoIP
              </span>
              <Sparkles size={14} className="text-emerald-400 group-hover:scale-110 transition-transform" />
            </div>
            <h4 className="text-sm font-semibold text-white group-hover:text-emerald-300 transition-colors">
              Global Cloud Perimeter
            </h4>
            <p className="text-xs text-zinc-400 leading-relaxed line-clamp-2">
              Public IP infrastructure across US, Europe, Japan, Singapore, and Australia with international traceroute latency paths.
            </p>
          </div>

          <div
            onClick={() => handleProcessXml(SAMPLE_SCANS.breachDiff.xmlB, 'Post-Incident Scan (Breach)')}
            className="p-4 rounded-xl bg-zinc-900/60 border border-zinc-800 hover:border-rose-500/60 cursor-pointer transition-all hover:bg-zinc-850 group space-y-2"
          >
            <div className="flex items-center justify-between">
              <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-400 text-[10px] font-bold uppercase border border-rose-800/50">
                Security Alert
              </span>
              <Sparkles size={14} className="text-rose-400 group-hover:scale-110 transition-transform" />
            </div>
            <h4 className="text-sm font-semibold text-white group-hover:text-rose-300 transition-colors">
              Security Breach Incident
            </h4>
            <p className="text-xs text-zinc-400 leading-relaxed line-clamp-2">
              Scan with backdoor port 4444 open, rogue implant host 10.0.10.99, and unencrypted telnet port 23 enabled.
            </p>
          </div>
        </div>
      )}

      {/* UPLOAD FILE TAB */}
      {activeTab === 'upload' && (
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setIsDragging(true);
          }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={`border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-all ${
            isDragging
              ? 'border-sky-400 bg-sky-950/20'
              : 'border-zinc-800 hover:border-zinc-700 bg-zinc-900/30 hover:bg-zinc-900/50'
          }`}
        >
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileChange}
            accept=".xml,.txt"
            className="hidden"
          />
          <Upload size={32} className="mx-auto text-sky-400 mb-3 animate-pulse" />
          <p className="text-sm font-medium text-white mb-1">
            Drag & drop your Nmap XML file here, or click to browse
          </p>
          <p className="text-xs text-zinc-500 font-mono">Accepts .xml generated by nmap -oX output.xml</p>
        </div>
      )}

      {/* PASTE XML TAB */}
      {activeTab === 'paste' && (
        <div className="space-y-3">
          <textarea
            rows={7}
            placeholder="Paste raw <?xml version='1.0' ...?> <nmaprun> content here..."
            value={pastedXml}
            onChange={(e) => setPastedXml(e.target.value)}
            className="w-full p-3.5 rounded-xl bg-zinc-900 border border-zinc-800 text-xs font-mono text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-sky-500"
          />
          <button
            onClick={() => handleProcessXml(pastedXml, 'Pasted XML Scan')}
            disabled={!pastedXml.trim()}
            className="px-5 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-xs font-semibold shadow transition-colors flex items-center gap-1.5 ml-auto"
          >
            <span>Parse & Visualize</span>
            <ArrowRight size={14} />
          </button>
        </div>
      )}
    </div>
  );
}
