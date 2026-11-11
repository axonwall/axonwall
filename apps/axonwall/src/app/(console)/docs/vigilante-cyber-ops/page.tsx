import React from 'react';
import Link from 'next/link';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';
import {
  ShieldAlert,
  Shield,
  Eye,
  Database,
  Network,
  Lock,
  Layers,
  Activity,
  Terminal,
  Sparkles,
} from 'lucide-react';

export const metadata = {
  title: 'Vigilante Cyber Defense, Autonomous SOC & SOAR | Axonwall Documentation',
  description:
    'Technical documentation for Vigilante Cyber Defense (core-vigilante): 12 modular K3s security packages, priority -10 nftables SOAR containment, Shannon-entropy ransomware pod freeze, honeytoken deception mesh, ZFS Merkle evidence vault, multi-node CTI federation, and the 106-tool Vigilante MCP server.',
};

export default function VigilanteCyberOpsDocPage() {
  return (
    <div className="space-y-12">
      {/* Page Header */}
      <div className="space-y-4 border-b border-slate-800 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-rose-950/60 border border-rose-500/30 text-rose-300 text-xs font-semibold">
          <ShieldAlert className="w-3.5 h-3.5" /> Core Role: core-vigilante • Autonomous SOC, SOAR &amp; Deception
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Vigilante Cyber Defense, Autonomous SOC &amp; Active SOAR
        </h1>
        <p className="text-base text-slate-400 leading-relaxed max-w-3xl">
          The <code className="text-emerald-400 font-mono">core-vigilante</code> Core Role turns your Axonwall appliance
          into an autonomous Security Operations Center (SOC), kernel-enforced SOAR responder, deception honeynet, and
          forensic evidence vault. Configured declaratively in{' '}
          <code className="text-emerald-400 font-mono">/etc/axonwall/vigilante.yaml</code> (with automatic{' '}
          <code className="text-slate-200 font-mono">core-k3s</code> dependency activation), Vigilante fuses network
          IDS/NSM sensors, eBPF runtime detection, multi-agent AI triage, and cryptographic chain-of-custody storage.
        </p>
      </div>

      {/* 1. Battlestation & 12 Modular K3s Security Packages */}
      <section id="battlestation" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Layers className="w-6 h-6 text-emerald-400" /> 1. Vigilante Battlestation &amp; 12 Modular K3s Packages
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Vigilante operates across three global enforcement postures (<code className="text-slate-200 font-mono">monitoring</code>,{' '}
          <code className="text-emerald-400 font-mono">hybrid</code>, and <code className="text-rose-400 font-mono">enforcing</code>)
          and orchestrates <strong className="text-white">12 modular Kubernetes security packages</strong> inside the
          isolated <code className="text-slate-200 font-mono">vigilante-soc</code> namespace—backed by OpenEBS{' '}
          <code className="text-slate-200 font-mono">axonwall-zfs-local</code> or synchronous 2-node{' '}
          <code className="text-slate-200 font-mono">axonwall-replicated-ha</code> PersistentVolumeClaims:
        </p>

        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-900/90 border-b border-slate-800 text-slate-300">
                <th className="py-3 px-4 font-bold">Module ID</th>
                <th className="py-3 px-4 font-bold">Default PVC</th>
                <th className="py-3 px-4 font-bold">Cyber-Defense Capability</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              <tr>
                <td className="py-3 px-4 font-mono text-emerald-400 font-semibold">vigil-soc / vigil-local</td>
                <td className="py-3 px-4 font-mono">20 GiB / 5 GiB</td>
                <td className="py-3 px-4">
                  Autonomous multi-agent AI SOC War Room orchestrator paired with air-gapped on-appliance local SLM triage (<code className="font-mono">vigil-local</code>).
                </td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-mono text-sky-400 font-semibold">opensearch / wazuh</td>
                <td className="py-3 px-4 font-mono">50 GiB / 30 GiB</td>
                <td className="py-3 px-4">
                  Distributed SIEM log analytics index (<code className="font-mono">opensearch</code>) and unified XDR, FIM, and compliance correlation (<code className="font-mono">wazuh</code>).
                </td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-mono text-amber-400 font-semibold">suricata / zeek / falco</td>
                <td className="py-3 px-4 font-mono">10 / 10 / 5 GiB</td>
                <td className="py-3 px-4">
                  Deep packet IDS/IPS alerts (<code className="font-mono">suricata</code>), L7 protocol transaction logs &amp; file carving (<code className="font-mono">zeek</code>), and eBPF syscall anomaly detection (<code className="font-mono">falco</code>).
                </td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-mono text-purple-400 font-semibold">bloodhound / openvas / zap</td>
                <td className="py-3 px-4 font-mono">15 / 30 / 5 GiB</td>
                <td className="py-3 px-4">
                  Active Directory &amp; IAM privilege-escalation attack-path graphing (<code className="font-mono">bloodhound</code>), network CVE scanning (<code className="font-mono">openvas</code>), and web DAST (<code className="font-mono">zap</code>).
                </td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-mono text-rose-400 font-semibold">flamingo / kctf</td>
                <td className="py-3 px-4 font-mono">5 GiB / 20 GiB</td>
                <td className="py-3 px-4">
                  Cloud-native deception &amp; canary listener pods (<code className="font-mono">flamingo</code>) and isolated Kubernetes CTF / Purple-Team exploit range (<code className="font-mono">kctf</code>).
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* 2. Kernel-Level SOAR Containment & Ransomware Freeze */}
      <section id="soar-containment" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Activity className="w-6 h-6 text-rose-400" /> 2. Kernel-Level SOAR Active Containment &amp; Ransomware Freeze
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Unlike cloud SIEMs that merely emit ticket notifications minutes after data exfiltration completes,{' '}
          <code className="text-emerald-400 font-mono">VigilanteManager</code> (<code className="text-slate-200 font-mono">engine/vigilante.go</code>)
          executes deterministic kernel and K3s containment in milliseconds governed by{' '}
          <code className="text-slate-200 font-mono">VigilanteSoarPolicySchema</code>:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-rose-400 text-sm flex items-center gap-2">
              <Shield className="w-4 h-4" /> Priority -10 nftables C2 Blocklists
            </div>
            <p className="text-slate-400 leading-relaxed">
              Vigilante hooks <code className="text-slate-200 font-mono">table inet axonwall</code>{' '}
              <code className="text-slate-200 font-mono">input</code> and{' '}
              <code className="text-slate-200 font-mono">forward</code> chains at{' '}
              <strong className="text-slate-200">priority <code className="font-mono">-10</code></strong> (pre-empting
              standard priority <code className="font-mono">0</code> pass rules). When{' '}
              <code className="text-slate-200 font-mono">autoBlockC2Ips</code> triggers, validated IPs/CIDRs (checked
              against <code className="text-slate-200 font-mono">ValidateTargetSafety</code> so appliance, gateway, and
              HA IPs are strictly immune) are injected into timeout-backed kernel sets (<code className="text-slate-200 font-mono">@vigilante_soar_block_v4</code>{' '}
              / <code className="text-slate-200 font-mono">@vigilante_soar_block_v6</code>, implemented as{' '}
              <code className="text-slate-200 font-mono">vigilante_soar_blocklist_v4/v6</code>).
            </p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-amber-400 text-sm flex items-center gap-2">
              <Lock className="w-4 h-4" /> Shannon-Entropy Ransomware Pod Freeze
            </div>
            <p className="text-slate-400 leading-relaxed">
              eBPF write-stream monitors compute sliding-window Shannon entropy deltas across NAS shares and PVC mounts.
              When a process spikes write entropy above{' '}
              <code className="text-slate-200 font-mono">ransomwareEntropyDeltaThreshold</code> (default{' '}
              <code className="text-slate-200 font-mono">2.0</code> bits/byte),{' '}
              <code className="text-slate-200 font-mono">autoFreezeRansomwarePods</code> immediately halts encryption in
              place via cgroup freezer / <code className="text-slate-200 font-mono">SIGSTOP</code> while{' '}
              <code className="text-slate-200 font-mono">autoIsolateCompromisedPods</code> applies a zero-egress
              NetworkPolicy quarantine.
            </p>
          </div>
        </div>

        <Callout type="info" title="Multi-Agent War Room Quorum Governance">
          High-impact autonomous containment actions generated by AI analysts require consensus across independent
          detection models meeting <code className="font-mono text-sky-300">warRoomQuorumThreshold</code> (default{' '}
          <code className="font-mono text-sky-300">0.75</code>, configurable from <code className="font-mono text-sky-300">0.50</code>{' '}
          to <code className="font-mono text-sky-300">1.00</code>) before transitioning from advisory staging to kernel
          enforcement.
        </Callout>
      </section>

      {/* 3. Deception Mesh, Honeytokens & Canary Directories */}
      <section id="deception-mesh" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Eye className="w-6 h-6 text-amber-400" /> 3. Deception Mesh, Honeytokens &amp; Canary Directories
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Zero-false-positive intrusion detection is achieved by seeding synthetic credentials, decoy listeners, and
          filesystem tripwires across the cluster (<code className="text-slate-200 font-mono">VigilanteDeceptionConfigSchema</code>):
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <div className="font-bold text-emerald-400">Canary ServiceAccounts</div>
            <p className="text-slate-400 leading-relaxed">
              Deploys high-value bait K8s identities (e.g. <code className="text-slate-200 font-mono">cluster-admin-backup</code>,{' '}
              <code className="text-slate-200 font-mono">vault-sync-sa</code>) watched by audit hooks; any API token
              use triggers instant pod isolation.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <div className="font-bold text-sky-400">Credential Honeytokens</div>
            <p className="text-slate-400 leading-relaxed">
              Generates tracked <code className="text-slate-200 font-mono">aws-sts</code>,{' '}
              <code className="text-slate-200 font-mono">github-pat</code>,{' '}
              <code className="text-slate-200 font-mono">slack-webhook</code>, and decoy{' '}
              <code className="text-slate-200 font-mono">kubeconfig</code> lure files that alert the SOC the moment an
              intruder attempts enumeration.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <div className="font-bold text-purple-400">Decoy Network Services</div>
            <p className="text-slate-400 leading-relaxed">
              Spins up instrumented <code className="text-slate-200 font-mono">smb</code>,{' '}
              <code className="text-slate-200 font-mono">ssh</code>,{' '}
              <code className="text-slate-200 font-mono">redis</code>, and{' '}
              <code className="text-slate-200 font-mono">mssql</code> traps—allowing{' '}
              <Link href="/docs/mcp-ai-control#tactical-leases" className="text-emerald-400 hover:underline">
                MCP DNAT redirection
              </Link>{' '}
              to steer live attackers into sandboxes.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <div className="font-bold text-rose-400">Ransomware Canary Dirs</div>
            <p className="text-slate-400 leading-relaxed">
              Places hidden canary bait files in NAS shares (<code className="text-slate-200 font-mono">ransomwareCanaryDirs</code>,
              e.g. <code className="text-slate-200 font-mono">/mnt/tank/shares</code>) to detect SMB/NFS lateral
              encryption on the very first file rename or overwrite.
            </p>
          </div>
        </div>
      </section>

      {/* 4. Tamper-Evident ZFS Forensic Evidence Vault & Sigma Data Lake */}
      <section id="evidence-vault" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Database className="w-6 h-6 text-sky-400" /> 4. Tamper-Evident ZFS Forensic Evidence Vault &amp; Sigma Data Lake
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          <code className="text-emerald-400 font-mono">ProvisionEvidenceVault</code> provisions a dedicated{' '}
          <code className="text-slate-200 font-mono">zstd</code>-compressed OpenZFS dataset (<code className="text-slate-200 font-mono">&lt;zfsPool&gt;/vigilante-evidence</code>)
          and strictly verifies that the dataset is mounted before writing forensic artifacts—refusing to silently spill
          sensitive captures onto the root filesystem:
        </p>

        <ul className="space-y-3 text-xs text-slate-300">
          <li className="p-4 rounded-xl bg-slate-900 border border-slate-800">
            <strong className="text-white block mb-1">
              SHA-256 Merkle Chain-of-Custody Ledger &amp; GPG Signing (<code className="text-emerald-400 font-mono">merkleLedgerEnabled: true</code>)
            </strong>
            Every captured PCAP ring segment, carved Zeek payload (<code className="text-slate-200 font-mono">carved/</code>),
            memory/process lineage snapshot, and SOAR action is hashed into an append-only SHA-256 Merkle tree under{' '}
            <code className="text-slate-200 font-mono">ledger/</code>, optionally signed with an offline-escrowed GPG key
            (<code className="text-slate-200 font-mono">gpgEnabled</code> / <code className="text-slate-200 font-mono">gpgKeyId</code>),
            and packaged as RFC 3161 timestamped court-ready evidence bundles or replicated to Axonwall Vault WORM S3 object lock.
          </li>
          <li className="p-4 rounded-xl bg-slate-900 border border-slate-800">
            <strong className="text-white block mb-1">
              Embedded SQLite / DuckDB Security Data Lake (<code className="text-sky-400 font-mono">dataLakeBackend</code>)
            </strong>
            Select lightweight transactional <code className="text-slate-200 font-mono">sqlite</code> or vectorized
            columnar <code className="text-slate-200 font-mono">duckdb</code> under{' '}
            <code className="text-slate-200 font-mono">datalake/</code> for high-speed Sigma rule hunting across millions
            of normalized Suricata EVE, Zeek, Falco, K3s audit, and OpenLDAP authentication events.
          </li>
        </ul>
      </section>

      {/* 5. Threat Federation, Zero-Touch LDAP RBAC & Vigilante MCP */}
      <section id="federation-mcp" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Sparkles className="w-6 h-6 text-purple-400" /> 5. Multi-Node Federation, LDAP RBAC &amp; Vigilante MCP Server
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Vigilante integrates natively with Axonwall&apos;s multi-site fleet mesh, embedded OpenLDAP directory, and
          autonomous AI tooling:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-white text-sm flex items-center gap-2">
              <Network className="w-4 h-4 text-emerald-400" /> Peer SOC Threat Federation
            </div>
            <p className="text-slate-400 leading-relaxed">
              Enable <code className="text-slate-200 font-mono">federation.enabled</code> to exchange signed IOCs and
              active C2 blocklists across peer Axonwall SOC nodes (<code className="text-slate-200 font-mono">autoIngestPeerBlocks: true</code>)
              so a compromise detected at one branch immunizes the entire enterprise fleet.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-white text-sm flex items-center gap-2">
              <Lock className="w-4 h-4 text-sky-400" /> Zero-Touch OpenLDAP RBAC
            </div>
            <p className="text-slate-400 leading-relaxed">
              Automatically provisions service account <code className="text-slate-200 font-mono">svc-vigilante</code>{' '}
              and POSIX groups <code className="text-slate-200 font-mono">vigilante-admin</code> (<code className="font-mono">10230</code>),{' '}
              <code className="text-slate-200 font-mono">vigilante-operator</code> (<code className="font-mono">10231</code>),
              and <code className="text-slate-200 font-mono">vigilante-readonly</code> (<code className="font-mono">10232</code>),
              propagating SSO bindings into OpenSearch, Wazuh, and Vigil-SOC (<Link href="/docs/identity-openldap-sso#plugin-federation" className="text-emerald-400 hover:underline">Identity Docs</Link>).
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-white text-sm flex items-center gap-2">
              <Terminal className="w-4 h-4 text-purple-400" /> 106-Tool Vigilante MCP Server
            </div>
            <p className="text-slate-400 leading-relaxed">
              Exposes <strong className="text-slate-200">18 static resources</strong>,{' '}
              <strong className="text-slate-200">5 URI templates</strong>, and{' '}
              <strong className="text-slate-200">106 specialized cyber-ops tools</strong> covering Sigma hunting, MITRE
              ATT&amp;CK Purple Team atomic simulations, kCTF range scoring, BloodHound path queries, and forensic
              evidence sealing.
            </p>
          </div>
        </div>

        <CodeBlock
          title="/etc/axonwall/vigilante.yaml"
          language="yaml"
          code={`vigilante:
  enabled: true
  posture: "hybrid"
  domain: "soc.axonwall.local"

  modules:
    - id: "vigil-soc"
      enabled: true
      namespace: "vigilante-soc"
      storageClass: "axonwall-replicated-ha"
      storageSizeGb: 20
    - id: "vigil-local"
      enabled: true
      namespace: "vigilante-soc"
      storageClass: "axonwall-zfs-local"
      storageSizeGb: 10
    - id: "opensearch"
      enabled: true
      namespace: "vigilante-soc"
      storageClass: "axonwall-zfs-local"
      storageSizeGb: 80
    - id: "wazuh"
      enabled: true
      namespace: "vigilante-soc"
      storageClass: "axonwall-replicated-ha"
      storageSizeGb: 40
    - id: "falco"
      enabled: true
      namespace: "vigilante-soc"
      storageClass: "axonwall-zfs-local"
      storageSizeGb: 5
    - id: "suricata"
      enabled: true
      namespace: "vigilante-soc"
      storageClass: "axonwall-zfs-local"
      storageSizeGb: 15
    - id: "zeek"
      enabled: true
      namespace: "vigilante-soc"
      storageClass: "axonwall-zfs-local"
      storageSizeGb: 20
    - id: "bloodhound"
      enabled: true
      namespace: "vigilante-soc"
      storageClass: "axonwall-zfs-local"
      storageSizeGb: 15
    - id: "flamingo"
      enabled: true
      namespace: "vigilante-soc"
      storageClass: "axonwall-zfs-local"
      storageSizeGb: 5
    - id: "zap"
      enabled: false
      namespace: "vigilante-soc"
      storageClass: "axonwall-zfs-local"
      storageSizeGb: 5
    - id: "kctf"
      enabled: false
      namespace: "vigilante-soc"
      storageClass: "axonwall-zfs-local"
      storageSizeGb: 20
    - id: "openvas"
      enabled: false
      namespace: "vigilante-soc"
      storageClass: "axonwall-zfs-local"
      storageSizeGb: 30

  soar:
    autoBlockC2Ips: true
    autoIsolateCompromisedPods: true
    autoFreezeRansomwarePods: true
    ransomwareEntropyDeltaThreshold: 2.0
    warRoomQuorumThreshold: 0.75
    blocklistTimeoutSeconds: 86400

  deception:
    enabled: true
    canaryServiceAccounts:
      - "cluster-admin-backup"
      - "vault-sync-sa"
    honeytokens:
      - "aws-sts"
      - "github-pat"
      - "kubeconfig"
    decoyServices:
      - "ssh"
      - "smb"
      - "redis"
    ransomwareCanaryDirs:
      - "/mnt/tank/shares"

  evidenceVault:
    zfsPool: "tank"
    datasetName: "vigilante-evidence"
    dataLakeBackend: "duckdb"
    gpgEnabled: true
    gpgKeyId: "0x9F4B8C2E1A7D3041"
    merkleLedgerEnabled: true

  federation:
    enabled: true
    nodeName: "axonwall-soc-hq"
    peers:
      - "https://10.255.0.2:2966"
    autoIngestPeerBlocks: true

  ldapAuth:
    enabled: true
    autoProvisionPrincipals: true
    allowLocalBreakGlass: true
    defaultRole: "viewer"
    syncModuleSso: true`}
        />

        <Callout type="tip" title="Access Vigilante Workspaces in Web Console, TUI & CLI">
          Open the live Attack Graph, SOAR Playbook Queue, Deception Mesh, Purple-Team Range, and Forensic Evidence
          Vault at <code className="font-mono text-emerald-300">/vigilante/battlestation</code>, in the Neovim Super
          Configurator via <code className="font-mono text-emerald-300">axonwall-config vigilante</code>, or on Tab{' '}
          <code className="font-mono text-emerald-300">[7] Compute &amp; SOC</code> of{' '}
          <code className="font-mono text-emerald-300">axonwall-tui</code>.
        </Callout>
      </section>
    </div>
  );
}
