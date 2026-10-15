'use client';

import React from 'react';
import { DocsSidebar } from './components/DocsSidebar';

export default function DocsLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex -m-6 min-h-[calc(100vh-4rem)]">
      {/* Docs Left Navigation Sidebar */}
      <div className="hidden lg:block w-72 shrink-0 border-r border-slate-800 bg-slate-900/60 sticky top-16 h-[calc(100vh-4rem)]">
        <DocsSidebar />
      </div>

      {/* Docs Content Body */}
      <main className="flex-1 min-w-0 p-8 max-w-4xl mx-auto">
        {children}
      </main>
    </div>
  );
}
