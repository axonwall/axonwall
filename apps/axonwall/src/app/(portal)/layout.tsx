import React from 'react';

export default function PortalLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 flex flex-col items-center pt-20">
      <header className="mb-10 text-center">
        <h1 className="text-3xl font-bold tracking-tight text-white">Axonwall Self-Service Portal</h1>
        <p className="text-slate-400 mt-2">Manage your devices and secure connectivity</p>
      </header>
      <main className="w-full max-w-3xl">
        {children}
      </main>
    </div>
  );
}
