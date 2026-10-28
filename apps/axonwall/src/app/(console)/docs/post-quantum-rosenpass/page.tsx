import React from 'react';
import Link from 'next/link';
import { KeyRound, Shield, Lock, RefreshCw, Network, Terminal, Zap } from 'lucide-react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'Post-Quantum Rosenpass Dual-KEM WireGuard VPN | Axonwall Documentation',
  description:
    'Protect site-to-site and mesh VPN tunnels against Harvest-Now-Decrypt-Later (HNDL) quantum adversaries using Rosenpass Dual-KEM (Classic McEliece 460896 + Kyber-768 / ML-KEM) with in-kernel Linux WireGuard.',
};

export default function PostQuantumRosenpassDocPage() {
  return (
    <div className="space-y-12">
      {/* Page Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Post-Quantum Cryptography (PQC) • Hybrid Dual-KEM
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          Post-Quantum Rosenpass Dual-KEM WireGuard Mesh
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Defend critical site-to-site and SD-Branch tunnels against <strong>Harvest Now, Decrypt Later (HNDL)</strong>{' '}
          quantum adversaries. Axonwall&apos;s <code className="text-emerald-400 font-mono">vpn-rosenpass</code> plugin pairs
          user-space <strong>Classic McEliece 460896</strong> (code-based KEM) and <strong>Kyber-768 / ML-KEM-768</strong>{' '}
          (lattice-based KEM) with the ultra-fast in-kernel Linux <code className="text-white font-mono">WireGuard</code>{' '}
          data plane.
        </p>
      </div>

      {/* Why Hybrid Post-Quantum WireGuard */}
      <section id="architecture" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <KeyRound className="w-6 h-6 text-emerald-400" /> 1. Why Classical X25519 Needs a Dual-KEM Upgrade
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Standard WireGuard uses the Noise_IKpsk2 handshake over <code className="text-white font-mono">Curve25519</code>{' '}
          (ECDHE) and encrypts transport packets with <code className="text-emerald-400 font-mono">ChaCha20-Poly1305</code>.
          While symmetric 256-bit <code className="text-white font-mono">ChaCha20</code> remains resistant to Grover&apos;s
          quantum search algorithm, <code className="text-rose-400 font-mono">X25519</code> elliptic-curve key agreement
          is vulnerable to Shor&apos;s algorithm on a Cryptographically Relevant Quantum Computer (CRQC).
        </p>
        <p className="text-sm text-slate-300 leading-relaxed">
          By feeding a continuously rotated 256-bit Post-Quantum Pre-Shared Key (<code className="text-emerald-400 font-mono">PSK</code>)
          derived from two orthogonal mathematical families—<strong>Classic McEliece 460896</strong> (Goppa codes) and{' '}
          <strong>Kyber-768</strong> (Module-LWE lattices)—directly into the kernel WireGuard interface every 120 seconds,
          Axonwall achieves post-quantum forward secrecy without sacrificing a single megabit of in-kernel WireGuard
          throughput.
        </p>

        <CodeBlock
          title="Hybrid Rosenpass Dual-KEM + Kernel WireGuard Architecture"
          language="text"
          code={`+-------------------------------------------------------------------------+
|  USERSPACE CONTROL PLANE: rosenpass daemon (UDP :9999)                  |
|  • Classic McEliece 460896 (Code-Based KEM — 524 KB Static Public Key)  |
|  • Kyber-768 / ML-KEM-768 (Lattice-Based Ephemeral KEM)                 |
|  • Blake2s Key Derivation -> Rotates 256-bit PSK every 120 seconds      |
+------------------------------------+------------------------------------+
                                     | wg set wg0 peer <PUB> preshared-key
                                     v
+-------------------------------------------------------------------------+
|  LINUX KERNEL DATA PLANE: wireguard.ko (UDP :51820)                     |
|  • Noise_IKpsk2 (X25519 + Rosenpass PQ-PSK)                             |
|  • ChaCha20-Poly1305 SIMD / AVX-512 Wire-Speed Packet Encryption        |
+-------------------------------------------------------------------------+`}
        />
      </section>

      {/* Step-by-Step Configuration */}
      <section id="configuration" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Lock className="w-6 h-6 text-emerald-400" /> 2. Configuring Post-Quantum Rosenpass Peers
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Enable the <code className="text-emerald-400 font-mono">vpn-rosenpass</code> plugin in{' '}
          <Link href="/system/plugins" className="text-emerald-400 underline">/system/plugins</Link> (or via{' '}
          <code className="text-emerald-400 font-mono">axonwall-config rosenpass</code>), then declare your Rosenpass
          listener and peers in <code className="text-emerald-400 font-mono">/etc/axonwall/rosenpass.yaml</code>:
        </p>

        <CodeBlock
          title="/etc/axonwall/rosenpass.yaml"
          language="yaml"
          code={`enabled: true
interface: wg0
listenPort: 9999
rekeyIntervalSec: 120
kemVariant: "classic-mceliece-460896+kyber768"
logLevel: "info"
keyDir: "/var/lib/axonwall/secrets/rosenpass"

peers:
  - name: "hq-zurich-core01"
    wgPeerPublicKey: "7xK9pL2mN4qR8sT1vW3xY5zA7bC9dE1fG3hJ5kL7mN0="
    endpoint: "198.51.100.10:9999"
    publicKeyPath: "/var/lib/axonwall/secrets/rosenpass/peers/hq-zurich-core01.pqpub"
    pskOutputMode: "wg-inject"`}
        />

        <Callout type="tip" title="Three Ways to Manage Rosenpass Keys & Peers">
          <ul className="list-disc list-inside space-y-1">
            <li>
              <strong>Web Console:</strong> Navigate to{' '}
              <Link href="/vpn/rosenpass" className="font-mono text-emerald-300 underline">/vpn/rosenpass</Link> to
              generate McEliece+Kyber keypairs, export peer public keys, and monitor live PSK rotation epochs.
            </li>
            <li>
              <strong>Neovim Super Configurator:</strong> Run{' '}
              <code className="font-mono text-emerald-300">axonwall-config rosenpass</code> (or{' '}
              <code className="font-mono text-emerald-300">axonwall-config wireguard</code>) over SSH.
            </li>
            <li>
              <strong>CLI Verification:</strong> Run{' '}
              <code className="font-mono text-emerald-300">axonwallctl rosenpass-status</code> and{' '}
              <code className="font-mono text-emerald-300">wg show wg0</code> to confirm active <code className="font-mono">preshared key: (hidden)</code>{' '}
              injection.
            </li>
          </ul>
        </Callout>
      </section>
    </div>
  );
}
