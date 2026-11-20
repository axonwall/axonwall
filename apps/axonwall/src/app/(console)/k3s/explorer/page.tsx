import React, { Suspense } from 'react';
import { K9sExplorerWorkbench } from '@/components/k3s/K9sExplorerWorkbench';

export const dynamic = 'force-dynamic';

export default function K3sExplorerPage() {
  return (
    <Suspense
      fallback={
        <div className="p-8 max-w-7xl mx-auto text-xs font-mono text-slate-400">
          Initializing K9s Browser Cockpit...
        </div>
      }
    >
      <K9sExplorerWorkbench />
    </Suspense>
  );
}
