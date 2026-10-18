'use client';

import React, { useState, useEffect, useRef } from 'react';
import { useParams, useSearchParams } from 'next/navigation';
import {
  Terminal,
  Monitor,
  Maximize2,
  RotateCcw,
  Power,
  Square,
  AlertCircle,
  CheckCircle2,
  RefreshCw,
} from 'lucide-react';
import { vmPowerAction } from '@/server/virt';

export default function WorkloadConsolePage() {
  const params = useParams();
  const searchParams = useSearchParams();

  const vmid = Number(params?.vmid || 100);
  const initialType = (searchParams?.get('type') || 'vnc') as 'vnc' | 'serial';

  const [consoleType, setConsoleType] = useState<'vnc' | 'serial'>(initialType);
  const [status, setStatus] = useState<'connecting' | 'connected' | 'disconnected' | 'error'>('connecting');
  const [logMessages, setLogMessages] = useState<string[]>([]);
  const [inputBuffer, setInputBuffer] = useState('');

  const terminalRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const connectWebSocket = () => {
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
      setLogMessages((prev) => [...prev, `[System] Connected to VM ${vmid} (${consoleType.toUpperCase()} console)`]);
    };

    ws.onmessage = (event) => {
      if (typeof event.data === 'string') {
        setLogMessages((prev) => [...prev.slice(-200), event.data]);
      } else if (event.data instanceof ArrayBuffer) {
        // Decode bytes to text for serial, or RFB frame
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
        `[Error] Connection failed to VM ${vmid} console. Is the VM online?`,
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

  const handleCtrlAltDel = () => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      // Send QEMU monitor sendkey ctrl-alt-delete or RFB key event
      wsRef.current.send(new Uint8Array([0x04, 0x01, 0xff, 0xe3])); // Ctrl-Alt-Del sequence
      setLogMessages((prev) => [...prev, '[Action] Sent Ctrl+Alt+Del']);
    }
  };

  const handlePower = async (action: 'stop' | 'reset', force = false) => {
    try {
      await vmPowerAction(vmid, action, force);
      setLogMessages((prev) => [...prev, `[Action] VM ${vmid} ${action} command sent.`]);
    } catch (err: any) {
      setLogMessages((prev) => [...prev, `[Error] ${err?.message || 'Power action failed'}`]);
    }
  };

  return (
    <div className="flex flex-col h-[calc(100vh-8rem)] rounded-xl bg-slate-950 border border-slate-800 overflow-hidden shadow-2xl">
      {/* Console Top Toolbar */}
      <div className="flex items-center justify-between px-4 py-3 bg-slate-900 border-b border-slate-800 text-sm">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 font-mono font-bold text-slate-100">
            {consoleType === 'vnc' ? (
              <Monitor className="w-4 h-4 text-cyan-400" />
            ) : (
              <Terminal className="w-4 h-4 text-emerald-400" />
            )}
            <span>VM {vmid} Console</span>
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
          {/* Console Mode Switcher */}
          <div className="flex items-center bg-slate-950 border border-slate-800 rounded-lg p-0.5 text-xs font-medium">
            <button
              onClick={() => setConsoleType('vnc')}
              className={`px-2.5 py-1 rounded transition-colors ${
                consoleType === 'vnc' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              VNC (HTML5)
            </button>
            <button
              onClick={() => setConsoleType('serial')}
              className={`px-2.5 py-1 rounded transition-colors ${
                consoleType === 'serial' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Serial (xterm)
            </button>
          </div>

          <button
            onClick={handleCtrlAltDel}
            className="px-2.5 py-1 text-xs font-mono font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded border border-slate-700 transition-colors"
            title="Send Ctrl+Alt+Del"
          >
            Ctrl+Alt+Del
          </button>

          <button
            onClick={() => handlePower('reset')}
            className="p-1.5 text-amber-400 hover:bg-amber-500/10 rounded transition-colors"
            title="Reset VM"
          >
            <RotateCcw className="w-4 h-4" />
          </button>

          <button
            onClick={() => handlePower('stop')}
            className="p-1.5 text-rose-400 hover:bg-rose-500/10 rounded transition-colors"
            title="Shutdown VM"
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
        {consoleType === 'vnc' ? (
          <div className="flex-1 flex flex-col items-center justify-center p-4">
            <canvas
              ref={canvasRef}
              width={1024}
              height={768}
              className="max-w-full max-h-full aspect-[4/3] border border-slate-800 rounded bg-slate-950 shadow-inner"
            />
            {status !== 'connected' && (
              <div className="absolute inset-0 flex flex-col items-center justify-center bg-slate-950/90 text-slate-300 space-y-3">
                <Monitor className="w-12 h-12 text-cyan-400 animate-pulse" />
                <p className="font-mono text-sm">
                  {status === 'connecting'
                    ? `Negotiating RFB VNC handshake for VM ${vmid}...`
                    : `VNC session inactive. Ensure VM ${vmid} is running.`}
                </p>
                {status !== 'connecting' && (
                  <button
                    onClick={connectWebSocket}
                    className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-semibold"
                  >
                    Retry Connection
                  </button>
                )}
              </div>
            )}
          </div>
        ) : (
          <div className="flex-1 flex flex-col min-h-0 p-4 font-mono text-xs text-emerald-400 bg-black">
            <div ref={terminalRef} className="flex-1 overflow-y-auto space-y-1 select-text">
              <div className="text-slate-500">
                # Axonwall VT100 Serial Virtual Terminal - VM {vmid}
              </div>
              <div className="text-slate-500">
                # Connected to /run/axonwall/serial/vm-{vmid}.sock
              </div>
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
        )}
      </div>
    </div>
  );
}
