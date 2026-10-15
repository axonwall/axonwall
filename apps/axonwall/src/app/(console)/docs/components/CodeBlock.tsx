'use client';

import React, { useState } from 'react';
import { Check, Copy } from 'lucide-react';

interface CodeBlockProps {
  title?: string;
  language?: string;
  code: string;
}

export function CodeBlock({ title, language = 'bash', code }: CodeBlockProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code.trim());
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback
      setCopied(false);
    }
  };

  return (
    <div className="my-5 rounded-xl border border-slate-800 bg-[#0d1322] overflow-hidden text-xs sm:text-sm font-mono shadow-xl">
      <div className="flex items-center justify-between px-4 py-2 border-b border-slate-800/80 bg-slate-900/60 text-slate-400">
        <div className="flex items-center gap-2">
          <div className="flex gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-slate-700/60" />
            <span className="w-2.5 h-2.5 rounded-full bg-slate-700/60" />
            <span className="w-2.5 h-2.5 rounded-full bg-slate-700/60" />
          </div>
          {title && <span className="text-slate-300 font-medium text-xs ml-2">{title}</span>}
        </div>
        <div className="flex items-center gap-3">
          {language && (
            <span className="text-[10px] uppercase font-semibold text-slate-500 tracking-wider">
              {language}
            </span>
          )}
          <button
            onClick={handleCopy}
            className="flex items-center gap-1.5 px-2 py-1 rounded text-xs text-slate-400 hover:text-white hover:bg-slate-800/80 transition cursor-pointer"
            title="Copy code"
            type="button"
          >
            {copied ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-400 text-[11px]">Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span className="text-[11px]">Copy</span>
              </>
            )}
          </button>
        </div>
      </div>
      <div className="p-4 overflow-x-auto text-slate-200 leading-relaxed font-mono">
        <pre>{code.trim()}</pre>
      </div>
    </div>
  );
}
