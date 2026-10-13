import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Axonwall Firewall & Router',
  description: 'Modern Linux & nftables Next-Generation Firewall',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `
              try {
                var tid = localStorage.getItem('axonwall_theme_id') || 'axonwall-emerald';
                document.documentElement.setAttribute('data-theme', tid);
              } catch (e) {}
            `,
          }}
        />
      </head>
      <body className="text-slate-100 antialiased selection:bg-emerald-500 selection:text-slate-950">
        {children}
      </body>
    </html>
  );
}
