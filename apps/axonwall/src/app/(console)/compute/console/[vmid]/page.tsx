'use client';

import React, { useState, useEffect, useRef } from 'react';
import { useParams, useSearchParams } from 'next/navigation';
import {
  Terminal,
  RotateCcw,
  Power,
  RefreshCw,
} from 'lucide-react';
import { vmPowerAction, containerPowerAction } from '@/server/virt';

export default function WorkloadConsolePage() {
  const params = useParams();
  const searchParams = useSearchParams();

  const vmid = Number(params?.vmid || 100);
  // D4: the workload kind must come from the link (?kind=vm|lxc). The old
  // `vmid >= 200` heuristic guessed wrong in both directions (VM 250 got
  // container power actions, CTID 100-199 got VM power actions), so a
  // missing/invalid kind fails closed instead of guessing.
  const kindParam = searchParams?.get('kind');
  const workloadKind: 'vm' | 'lxc' | null =
    kindParam === 'vm' || kindParam === 'lxc' ? kindParam : null;

  // D3: there is no VNC/RFB client in this build — the old VNC mode showed
  // a blank canvas and a "Negotiating RFB VNC handshake…" message while
  // decoding binary RFB frames as text. VNC mode is removed; VMs get the
  // serial console and containers get the LXC console the daemon actually
  // serves (type=lxc -> /run/axonwall/lxc/ct-<id>.sock, not type=serial).
  const consoleType: 'serial' | 'lxc' = workloadKind === 'lxc' ? 'lxc' : 'serial';
  const socketPath =
    workloadKind === 'lxc'
      ? `/run/axonwall/lxc/ct-${vmid}.sock`
      : `/run/axonwall/serial/vm-${vmid}.sock`;

  const [status, setStatus] = useState<'connecting' | 'connected' | 'disconnected' | 'error'>('connecting');
  const [logMessages, setLogMessages] = useState<string[]>([]);
  const [inputBuffer, setInputBuffer] = useState('');

  const terminalRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const connectWebSocket = () => {
    if (!workloadKind) {
      setStatus('error');
      setLogMessages((prev) => [
        ...prev,
        '[Error] Console link is missing the workload kind (?kind=vm or ?kind=lxc). Refusing to guess which workload to power-cycle.',
      ]);
      return;
    }
    setStatus('connecting');
    if (wsRef.current) {
      wsRef.current.close();
    }

    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    // In dev / production, connects to the agent's websocket proxy endpoint
    const wsUrl = `${proto}//${window.location.host}/v1/virt/console/ws?vmid=${vmid}&type=${consoleType}`;

    const ws = new WebSocket(wsUrl);
    ws.binaryType = 'arraybuffer';
    wsRef.current = ws;

    ws.onopen = () => {
      setStatus('connected');
      setLogMessages((prev) => [...prev, `[System] Connected to ${workloadKind === 'lxc' ? 'container' : 'VM'} ${vmid} (${consoleType.toUpperCase()} console)`]);
    };

    ws.onmessage = (event) => {
      if (typeof event.data === 'string') {
        setLogMessages((prev) => [...prev.slice(-200), event.data]);
      } else if (event.data instanceof ArrayBuffer) {
        // Decode bytes to text for the serial / LXC console.
        const text = new TextDecoder('utf-8').decode(event.data);
        setLogMessages((prev) => [...prev.slice(-200), text]);
      }
      if (terminalRef.current) {
        terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
      }
    };

    ws.onerror = () => {
      setStatus('error');
      setLogMessages((prev) => [
        ...prev,
        `[Error] Connection failed to ${workloadKind === 'lxc' ? 'container' : 'VM'} ${vmid} console. Is the workload online?`,
      ]);
    };

    ws.onclose = () => {
      setStatus('disconnected');
      setLogMessages((prev) => [...prev, `[System] Console session closed.`]);
    };
  };

  useEffect(() => {
    connectWebSocket();
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [vmid, consoleType]);

  const sendTerminalInput = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputBuffer) return;
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(inputBuffer + '\n');
    } else {
      setLogMessages((prev) => [...prev, `$ ${inputBuffer}`]);
    }
    setInputBuffer('');
  };

  const handlePower = async (action: 'stop' | 'reset', force = false) => {
    if (!workloadKind) return;
    try {
      if (workloadKind === 'lxc') {
        const res = await containerPowerAction(vmid, action === 'reset' ? 'reboot' : 'stop', force);
        setLogMessages((prev) => [...prev, `[Action] ${res.message}`]);
      } else {
        const res = await vmPowerAction(vmid, action, force);
        setLogMessages((prev) => [...prev, `[Action] ${res.message}`]);
      }
    } catch (err: any) {
      setLogMessages((prev) => [...prev, `[Error] ${err?.message || 'Power action failed'}`]);
    }
  };

  if (!workloadKind) {
    return (
      <div className="flex flex-col h-[calc(100vh-8rem)] rounded-xl bg-slate-950 border border-red-500/40 overflow-hidden shadow-2xl items-center justify-center p-8 text-center space-y-3">
        <Terminal className="w-10 h-10 text-red-400" />
        <p className="font-semibold text-white">Console link is missing the workload kind</p>
        <p className="text-sm text-slate-400 max-w-md">
          This console cannot tell whether {vmid} is a VM or an LXC container, and guessing has
          previously power-cycled the wrong workload. Open the console from the VMs page (for a VM)
          or the LXC page (for a container), or add <code className="font-mono text-slate-200">?kind=vm</code> or{' '}
          <code className="font-mono text-slate-200">?kind=lxc</code> to the URL.
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-[calc(100vh-8rem)] rounded-xl bg-slate-950 border border-slate-800 overflow-hidden shadow-2xl">
      {/* Console Top Toolbar */}
      <div className="flex items-center justify-between px-4 py-3 bg-slate-900 border-b border-slate-800 text-sm">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 font-mono font-bold text-slate-100">
            <Terminal className="w-4 h-4 text-emerald-400" />
            <span>{workloadKind === 'lxc' ? `Container ${vmid} Console` : `VM ${vmid} Console`}</span>
          </div>

          <div className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border bg-slate-950">
            <span
              className={`w-2 h-2 rounded-full ${
                status === 'connected'
                  ? 'bg-emerald-400 animate-pulse'
                  : status === 'connecting'
                  ? 'bg-amber-400 animate-pulse'
                  : 'bg-rose-500'
              }`}
            />
            <span className="capitalize text-slate-300">{status}</span>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => handlePower('reset')}
            className="p-1.5 text-amber-400 hover:bg-amber-500/10 rounded transition-colors"
            title={workloadKind === 'lxc' ? 'Restart container' : 'Reset VM'}
          >
            <RotateCcw className="w-4 h-4" />
          </button>

          <button
            onClick={() => handlePower('stop')}
            className="p-1.5 text-rose-400 hover:bg-rose-500/10 rounded transition-colors"
            title={workloadKind === 'lxc' ? 'Stop container' : 'Shutdown VM'}
          >
            <Power className="w-4 h-4" />
          </button>

          <button
            onClick={connectWebSocket}
            className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded transition-colors"
            title="Reconnect"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Screen Area */}
      <div className="flex-1 bg-black relative flex flex-col min-h-0 overflow-hidden">
        <div className="flex-1 flex flex-col min-h-0 p-4 font-mono text-xs text-emerald-400 bg-black">
          <div className="text-slate-500">
            # Axonwall VT100 Serial Virtual Terminal - {workloadKind === 'lxc' ? `Container ${vmid}` : `VM ${vmid}`}
          </div>
          <div className="text-slate-500">
            # Connected to {socketPath}
          </div>
          <div className="text-slate-500">
            # Note: graphical VNC console is not implemented in this build — serial console only.
          </div>
          <div ref={terminalRef} className="flex-1 overflow-y-auto space-y-1 select-text mt-2">
            {logMessages.map((msg, idx) => (
              <div key={idx} className="whitespace-pre-wrap">
                {msg}
              </div>
            ))}
          </div>

          <form onSubmit={sendTerminalInput} className="mt-2 flex items-center gap-2 border-t border-slate-800 pt-2">
            <span className="text-cyan-400 font-bold">&gt;</span>
            <input
              type="text"
              value={inputBuffer}
              onChange={(e) => setInputBuffer(e.target.value)}
              placeholder="Type command and press Enter..."
              className="flex-1 bg-transparent border-0 text-slate-100 text-xs font-mono focus:ring-0 focus:outline-none"
            />
          </form>
        </div>
      </div>
    </div>
  );
}
