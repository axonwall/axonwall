'use client';

import React, { useMemo, useState } from 'react';
import { Search } from 'lucide-react';
import { validateFqlQuery } from '@axonwall/lib/compile/netflow';

interface SuggestionItem {
  insertText: string;
  label: string;
  hint: string;
  replaceStart: number;
  replaceEnd: number;
}

const FQL_FIELD_HINTS: Array<{ name: string; hint: string }> = [
  { name: 'src', hint: 'IP or CIDR' },
  { name: 'dst', hint: 'IP or CIDR' },
  { name: 'ip', hint: 'Src or Dst IP/CIDR' },
  { name: 'dst_port', hint: 'Port number' },
  { name: 'src_port', hint: 'Port number' },
  { name: 'port', hint: 'Src or Dst port' },
  { name: 'proto', hint: 'TCP | UDP | ICMP' },
  { name: 'app', hint: 'App name' },
  { name: 'direction', hint: 'internal | ingress | egress | transit' },
  { name: 'exporter', hint: 'Exporter IP' },
  { name: 'in_if', hint: 'Ingress interface' },
  { name: 'out_if', hint: 'Egress interface' },
  { name: 'vlan', hint: 'VLAN ID' },
  { name: 'bytes', hint: 'e.g. >1MB' },
  { name: 'packets', hint: 'Packet count' },
  { name: 'bps', hint: 'e.g. >10Mbps' },
  { name: 'country', hint: 'ISO code (US, DE, ...)' },
  { name: 'city', hint: 'MMDB City name' },
  { name: 'asn', hint: 'ASN or Org' },
  { name: 'peer_as', hint: 'BGP Peer AS' },
  { name: 'as_path', hint: 'BGP AS Path contains' },
  { name: 'post_nat_src', hint: 'Post-SNAT IP' },
  { name: 'post_nat_dst', hint: 'Post-DNAT IP' },
  { name: 'post_nat_sport', hint: 'Post-SNAT port' },
  { name: 'post_nat_dport', hint: 'Post-DNAT port' },
  { name: 'k3s_ns', hint: 'K3s Namespace' },
  { name: 'k3s_pod', hint: 'K3s Pod/Service' },
  { name: 'tcp_flags', hint: 'SYN | ACK | RST | FIN' },
  { name: 'rtt_ms', hint: 'TCP RTT ms' },
  { name: 'retransmits', hint: 'TCP retransmits' },
  { name: 'threat', hint: 'IOC alias match' },
  { name: 'host', hint: 'Resolved hostname' },
  { name: 'host_id', hint: 'Fleet Axonwall host' },
  { name: 'version', hint: 'ipfix | netflow9 | netflow5 | sflow5' },
];

export interface FqlLiveSuggestions {
  exporters?: string[];
  interfaces?: string[];
  apps?: string[];
  countries?: string[];
}

interface FqlInputBarProps {
  value: string;
  onChange: (next: string) => void;
  onSubmit: (val?: string) => void;
  placeholder?: string;
  live?: FqlLiveSuggestions;
}

export function FqlInputBar({
  value,
  onChange,
  onSubmit,
  placeholder = 'FQL: src=10.80.0.0/24 and (dst_port=443 or proto=tcp) and bytes>1MB',
  live,
}: FqlInputBarProps) {
  const [focused, setFocused] = useState(false);
  const [selectedIdx, setSelectedIdx] = useState(0);
  const fqlCheck = useMemo(() => validateFqlQuery(value), [value]);

  const suggestions = useMemo<SuggestionItem[]>(() => {
    if (!focused) return [];
    const trimmedRight = value;
    const len = trimmedRight.length;

    // 1. Field=partialValue or Field~partialValue at end of input
    const predMatch = /(?:^|[\s(])([a-zA-Z_][a-zA-Z0-9_]*)(=|!=|~|>|>=|<|<=)([^\s()]*)$/.exec(trimmedRight);
    if (predMatch) {
      const field = predMatch[1]!.toLowerCase();
      const partial = (predMatch[3] || '').toLowerCase();
      const valStart = len - (predMatch[3] || '').length;
      const candidates: Array<{ val: string; hint: string }> = [];

      if (field === 'proto' || field === 'protocol') {
        ['tcp', 'udp', 'icmp', 'icmpv6'].forEach((v) => candidates.push({ val: v, hint: 'L4 protocol' }));
      } else if (field === 'direction' || field === 'dir') {
        ['internal', 'ingress', 'egress', 'transit'].forEach((v) => candidates.push({ val: v, hint: 'Flow direction' }));
      } else if (field === 'tcp_flags' || field === 'flags') {
        ['SYN', 'ACK', 'RST', 'FIN', 'SYN|ACK'].forEach((v) => candidates.push({ val: v, hint: 'TCP flags' }));
      } else if (field === 'version') {
        ['ipfix', 'netflow9', 'netflow5', 'sflow5'].forEach((v) => candidates.push({ val: v, hint: 'Flow version' }));
      } else if (field === 'exporter' || field === 'exporter_ip') {
        (live?.exporters ?? []).forEach((v) => candidates.push({ val: v, hint: 'Live exporter' }));
      } else if (field === 'if' || field === 'in_if' || field === 'out_if') {
        (live?.interfaces ?? []).forEach((v) => candidates.push({ val: v, hint: 'Observed interface' }));
      } else if (field === 'app') {
        (live?.apps ?? []).forEach((v) => candidates.push({ val: v, hint: 'Observed app' }));
      } else if (field === 'country') {
        (live?.countries ?? []).forEach((v) => candidates.push({ val: v, hint: 'Country ISO' }));
      } else if (field === 'bytes') {
        ['1MB', '10MB', '100MB', '1GB'].forEach((v) => candidates.push({ val: v, hint: 'Size threshold' }));
      } else if (field === 'bps') {
        ['1Mbps', '10Mbps', '100Mbps', '1Gbps'].forEach((v) => candidates.push({ val: v, hint: 'Bitrate' }));
      }

      return candidates
        .filter((c) => !partial || c.val.toLowerCase().includes(partial))
        .slice(0, 8)
        .map((c) => ({
          insertText: c.val + ' ',
          label: c.val,
          hint: c.hint,
          replaceStart: valStart,
          replaceEnd: len,
        }));
    }

    // 2. Partial word at end -> suggest FQL fields or boolean combinators
    const wordMatch = /(?:^|[\s(])([a-zA-Z_][a-zA-Z0-9_]*)$/.exec(trimmedRight);
    const partialWord = (wordMatch?.[1] || '').toLowerCase();
    const wordStart = len - partialWord.length;

    // Suggest field= or operator suggestions if an exact field name was just typed cleanly
    const exactField = FQL_FIELD_HINTS.find((f) => f.name === partialWord);
    if (exactField && partialWord.length > 0) {
      return ['=', '!=', '~', '>', '<'].map((op) => ({
        insertText: op,
        label: `${partialWord}${op}`,
        hint: exactField.hint,
        replaceStart: len,
        replaceEnd: len,
      }));
    }

    return FQL_FIELD_HINTS.filter((f) => !partialWord || f.name.includes(partialWord))
      .slice(0, 8)
      .map((f) => ({
        insertText: `${f.name}=`,
        label: f.name,
        hint: f.hint,
        replaceStart: wordStart,
        replaceEnd: len,
      }));
  }, [focused, live, value]);

  const applySuggestion = (item: SuggestionItem) => {
    const next = value.slice(0, item.replaceStart) + item.insertText + value.slice(item.replaceEnd);
    onChange(next);
    setSelectedIdx(0);
  };

  return (
    <div className="relative flex-1 min-w-[260px]">
      <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
      <input
        type="text"
        value={value}
        onFocus={() => setFocused(true)}
        onBlur={() => setTimeout(() => setFocused(false), 150)}
        onChange={(e) => {
          onChange(e.target.value);
          setSelectedIdx(0);
        }}
        onKeyDown={(e) => {
          if (suggestions.length > 0) {
            if (e.key === 'ArrowDown') {
              e.preventDefault();
              setSelectedIdx((i) => (i + 1) % suggestions.length);
              return;
            }
            if (e.key === 'ArrowUp') {
              e.preventDefault();
              setSelectedIdx((i) => (i - 1 + suggestions.length) % suggestions.length);
              return;
            }
            if (e.key === 'Tab') {
              e.preventDefault();
              const pick = suggestions[selectedIdx] ?? suggestions[0];
              if (pick) applySuggestion(pick);
              return;
            }
            if (e.key === 'Escape') {
              setFocused(false);
              return;
            }
          }
          if (e.key === 'Enter' && fqlCheck.valid) {
            setFocused(false);
            onSubmit();
          }
        }}
        placeholder={placeholder}
        className={`w-full pl-9 pr-3 py-2 rounded-lg bg-slate-950 border text-xs font-mono text-white focus:outline-none ${
          fqlCheck.valid ? 'border-slate-700 focus:border-sky-500' : 'border-rose-500'
        }`}
      />

      {focused && suggestions.length > 0 && (
        <div className="absolute left-0 right-0 top-full mt-1 z-30 rounded-lg bg-slate-950 border border-slate-700 shadow-xl overflow-hidden text-xs">
          {suggestions.map((s, idx) => (
            <button
              key={`${s.label}-${idx}`}
              type="button"
              onMouseDown={(e) => {
                e.preventDefault();
                applySuggestion(s);
              }}
              className={`w-full px-3 py-1.5 flex items-center justify-between text-left ${
                idx === selectedIdx ? 'bg-sky-600/30 text-white' : 'text-slate-300 hover:bg-slate-900'
              }`}
            >
              <span className="font-mono text-sky-300">{s.label}</span>
              <span className="text-[11px] text-slate-400">{s.hint}</span>
            </button>
          ))}
          <div className="px-3 py-1 bg-slate-900 text-[10px] text-slate-400 font-mono flex justify-between">
            <span>↑↓ select · Tab autocomplete · Enter run query</span>
            <span>FQL v2</span>
          </div>
        </div>
      )}
    </div>
  );
}
