'use client';

import { useState, useRef } from 'react';
import {
  UploadCloud,
  CheckCircle2,
  AlertTriangle,
  FileText,
  Play,
  Download,
  Terminal,
  Layers,
  FileCode,
  Check,
  RefreshCw,
  ShieldAlert,
  ChevronLeft,
  ChevronRight,
  Trash2,
  Lock,
} from 'lucide-react';
import {
  importFirewallConfig,
  detectFirewallType,
  analyzeRuleShadowing,
  type FirewallVendor,
  type ImportReport,
  type RuleAnalysisReport,
} from '@axonwall/lib/import';
import { compileNftables } from '@axonwall/lib/compile/nft';

interface VendorOption {
  id: FirewallVendor | 'auto';
  label: string;
  badge: string;
  filename: string;
}

const VENDOR_OPTIONS: VendorOption[] = [
  { id: 'auto', label: 'Auto-Detect', badge: 'Smart', filename: 'Auto' },
  { id: 'pfsense', label: 'pfSense', badge: 'XML', filename: 'config.xml' },
  { id: 'opnsense', label: 'OPNsense', badge: 'XML', filename: 'config.xml' },
  { id: 'vyos', label: 'VyOS / EdgeOS', badge: 'boot/json', filename: 'config.boot' },
  { id: 'mikrotik', label: 'MikroTik RouterOS', badge: 'RSC', filename: 'export.rsc' },
  { id: 'cisco', label: 'Cisco ASA / FTD', badge: 'ACL', filename: 'running-config.cfg' },
  { id: 'iptables', label: 'Linux iptables', badge: 'save', filename: 'rules.v4' },
  { id: 'firewalld', label: 'Linux firewalld', badge: 'XML/CLI', filename: 'public.xml' },
];

const SAMPLE_CONFIGS: Record<FirewallVendor, string> = {
  pfsense: `<?xml version="1.0"?>
<pfsense>
  <version>23.09</version>
  <system>
    <hostname>pfsense-gateway</hostname>
    <domain>corp.internal</domain>
  </system>
  <interfaces>
    <wan><if>vtnet0</if><ipaddr>dhcp</ipaddr><descr>WAN_Uplink</descr></wan>
    <lan><if>vtnet1</if><ipaddr>192.168.10.1</ipaddr><subnet>24</subnet><descr>Corp_LAN</descr></lan>
    <opt1><if>vtnet2</if><ipaddr>172.16.50.1</ipaddr><subnet>24</subnet><descr>DMZ</descr></opt1>
  </interfaces>
  <vlans>
    <tag>
      <if>vtnet1</if>
      <tag>20</tag>
      <vlanif>vtnet1.20</vlanif>
      <descr>Guest_WiFi</descr>
    </tag>
  </vlans>
  <aliases>
    <alias>
      <name>WebServers</name>
      <type>host</type>
      <address>172.16.50.10 172.16.50.11</address>
      <descr>DMZ Web Cluster</descr>
    </alias>
    <alias>
      <name>AdminSubnet</name>
      <type>network</type>
      <address>192.168.10.0/28</address>
      <descr>Management Workstations</descr>
    </alias>
  </aliases>
  <filter>
    <rule>
      <type>pass</type>
      <interface>lan</interface>
      <protocol>tcp</protocol>
      <destination><port>443</port></destination>
      <descr>Allow Outbound HTTPS</descr>
    </rule>
    <rule>
      <type>pass</type>
      <interface>wan</interface>
      <protocol>tcp</protocol>
      <destination><network>WebServers</network><port>443</port></destination>
      <descr>Inbound HTTPS to DMZ Web</descr>
    </rule>
    <rule>
      <type>block</type>
      <interface>lan</interface>
      <protocol>any</protocol>
      <destination><network>10.0.0.0/8</network></destination>
      <descr>Block Access to Legacy Intranet</descr>
    </rule>
    <rule>
      <type>block</type>
      <interface>opt1</interface>
      <protocol>any</protocol>
      <source><any/></source>
      <destination><not/><network>lan</network></destination>
      <descr>Isolate DMZ from Non-LAN Subnets</descr>
    </rule>
  </filter>
  <nat>
    <rule>
      <interface>wan</interface>
      <protocol>tcp</protocol>
      <target>172.16.50.10</target>
      <local-port>8443</local-port>
      <destination><port>443</port></destination>
      <descr>Port Forward WAN:443 to DMZ:8443</descr>
    </rule>
  </nat>
  <dhcpd>
    <lan>
      <enable/>
      <range><from>192.168.10.100</from><to>192.168.10.200</to></range>
      <gateway>192.168.10.1</gateway>
      <staticmap>
        <mac>00:11:22:33:44:55</mac>
        <ipaddr>192.168.10.50</ipaddr>
        <hostname>nas01</hostname>
      </staticmap>
    </lan>
  </dhcpd>
  <unbound>
    <hosts>
      <host>gateway</host>
      <domain>corp.internal</domain>
      <ip>192.168.10.1</ip>
    </hosts>
    <hosts>
      <host>dc1</host>
      <domain>corp.internal</domain>
      <ip>192.168.10.5</ip>
    </hosts>
  </unbound>
  <staticroutes>
    <route>
      <network>10.50.0.0/16</network>
      <gateway>172.16.50.254</gateway>
      <descr>Site-to-Site Branch Tunnel</descr>
    </route>
  </staticroutes>
</pfsense>`,

  opnsense: `<?xml version="1.0"?>
<opnsense version="24.7">
  <system>
    <hostname>opnsense-core</hostname>
    <domain>lab.local</domain>
  </system>
  <interfaces>
    <wan><if>eth0</if><ipaddr>dhcp</ipaddr><descr>WAN</descr></wan>
    <lan><if>eth1</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet><descr>LAN</descr></lan>
  </interfaces>
  <aliases>
    <alias>
      <name>DNS_Servers</name>
      <type>host</type>
      <content>1.1.1.1&#10;8.8.8.8</content>
      <descr>Upstream Resolvers</descr>
    </alias>
  </aliases>
  <filter>
    <rule>
      <type>pass</type>
      <interface>lan</interface>
      <protocol>tcp</protocol>
      <destination><port>443</port></destination>
      <descr>Allow HTTPS</descr>
    </rule>
    <rule>
      <type>pass</type>
      <interface>lan</interface>
      <protocol>udp</protocol>
      <destination><network>DNS_Servers</network><port>53</port></destination>
      <descr>Allow DNS to Upstream</descr>
    </rule>
  </filter>
  <nat>
    <rule>
      <interface>wan</interface>
      <protocol>tcp</protocol>
      <target>192.168.1.50</target>
      <local-port>22</local-port>
      <destination><port>2222</port></destination>
      <descr>SSH Port Forward</descr>
    </rule>
  </nat>
  <dhcpd>
    <lan>
      <enable>1</enable>
      <range><from>192.168.1.100</from><to>192.168.1.200</to></range>
      <gateway>192.168.1.1</gateway>
    </lan>
  </dhcpd>
</opnsense>`,

  vyos: `interfaces {
    ethernet eth0 {
        address dhcp
        description "Internet WAN"
    }
    ethernet eth1 {
        address 192.168.100.1/24
        description "Corporate LAN"
        vif 30 {
            address 10.30.0.1/24
            description "VoIP VLAN"
        }
    }
}
firewall {
    group {
        address-group BOGONS {
            address 100.64.0.0/10
            address 198.18.0.0/15
        }
    }
    name WAN_IN {
        default-action drop
        rule 10 {
            action accept
            state {
                established enable
                related enable
            }
            description "Allow Established/Related"
        }
        rule 20 {
            action accept
            protocol tcp
            destination {
                port 443
            }
            description "Allow HTTPS Inbound"
        }
        rule 30 {
            action drop
            source {
                group {
                    address-group BOGONS
                }
            }
            description "Drop Bogon Sources"
        }
    }
}
nat {
    destination {
        rule 100 {
            inbound-interface eth0
            protocol tcp
            destination {
                port 8443
            }
            translation {
                address 192.168.100.50
                port 443
            }
        }
    }
    source {
        rule 100 {
            outbound-interface eth0
            translation {
                address masquerade
            }
        }
    }
}
service {
    dhcp-server {
        shared-network-name LAN_POOL {
            subnet 192.168.100.0/24 {
                default-router 192.168.100.1
                range 0 {
                    start 192.168.100.100
                    stop 192.168.100.200
                }
            }
        }
    }
}
protocols {
    static {
        route 172.16.0.0/16 {
            next-hop 192.168.100.254 {
            }
        }
    }
}`,

  mikrotik: `# RouterOS export
/system identity set name="Mikrotik-HQ"
/interface vlan add interface=ether2 name=vlan20-guest vlan-id=20
/ip address add address=192.168.88.1/24 interface=ether2 network=192.168.88.0
/ip address add address=10.20.0.1/24 interface=vlan20-guest network=10.20.0.0
/ip pool add name=dhcp-pool-lan ranges=192.168.88.100-192.168.88.200
/ip dhcp-server add address-pool=dhcp-pool-lan interface=ether2 name=dhcp-lan
/ip dhcp-server network add address=192.168.88.0/24 gateway=192.168.88.1
/ip firewall address-list add address=192.168.88.50 list=TrustedAdmins
/ip firewall filter add chain=input action=accept protocol=tcp dst-port=22,443 src-address-list=TrustedAdmins comment="Allow Admin Management"
/ip firewall filter add chain=forward action=accept connection-state=established,related comment="Accept Established"
/ip firewall filter add chain=forward action=drop connection-state=invalid comment="Drop Invalid"
/ip firewall filter add chain=forward action=drop in-interface=vlan20-guest out-interface=ether2 comment="Isolate Guest from LAN"
/ip firewall nat add chain=srcnat action=masquerade out-interface=ether1 comment="WAN Outbound NAT"
/ip firewall nat add chain=dstnat action=dst-nat protocol=tcp dst-port=8080 to-addresses=192.168.88.50 to-ports=80 comment="Port Forward HTTP"
/ip dns static add address=192.168.88.1 name=router.lan
/ip route add dst-address=172.16.0.0/12 gateway=192.168.88.254 comment="Core Route"`,

  iptables: `# Generated by iptables-save
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT -m comment --comment "Accept established connections"
-A INPUT -i lo -j ACCEPT -m comment --comment "Allow loopback"
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT -m comment --comment "Allow SSH management"
-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT -m comment --comment "Allow Web UI"
-A INPUT -p icmp -j ACCEPT -m comment --comment "Allow ping"
-A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A FORWARD -i eth1 -o eth0 -j ACCEPT -m comment --comment "Allow LAN outbound to WAN"
-A FORWARD -i eth0 -o eth1 -p tcp --dport 80 -d 192.168.1.100 -j ACCEPT -m comment --comment "Forward HTTP to Web Server"
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A PREROUTING -i eth0 -p tcp --dport 80 -j DNAT --to-destination 192.168.1.100:80
COMMIT`,

  cisco: `interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address dhcp
!
interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 192.168.10.1 255.255.255.0
!
interface GigabitEthernet0/1.50
 vlan 50
 nameif dmz
 security-level 50
 ip address 172.16.50.1 255.255.255.0
!
object network WebServer
 host 172.16.50.10
 description Production Web Server
!
object-group network AdminHosts
 network-object host 192.168.10.5
 network-object 192.168.10.64 255.255.255.192
!
access-list outside_in extended permit tcp any host 172.16.50.10 eq 443
access-list outside_in extended permit icmp any any
access-list outside_in extended deny ip any any
access-list inside_in extended permit ip any any
!
nat (inside,outside) source dynamic any interface
nat (outside,dmz) source static any any destination static interface WebServer
!
route inside 10.0.0.0 255.0.0.0 192.168.10.254 1`,

  firewalld: `<?xml version="1.0" encoding="utf-8"?>
<ipset type="hash:net" name="trusted_admins">
  <short>Trusted Admin Subnets</short>
  <entry>10.80.0.0/24</entry>
  <entry>192.168.10.50/32</entry>
</ipset>
<zone name="public" target="default">
  <short>Public WAN</short>
  <description>Public facing untrusted interface</description>
  <interface name="eth0"/>
  <service name="ssh"/>
  <service name="https"/>
  <service name="wireguard"/>
  <port port="8443" protocol="tcp"/>
  <masquerade/>
  <forward-port port="80" protocol="tcp" to-port="8080" to-addr="192.168.1.50"/>
  <rule family="ipv4">
    <source ipset="trusted_admins"/>
    <service name="cockpit"/>
    <log prefix="ADMIN_COCKPIT: "/>
    <accept/>
  </rule>
  <rule family="ipv4">
    <source address="198.51.100.99"/>
    <drop/>
  </rule>
</zone>
<zone name="internal" target="ACCEPT">
  <short>Internal Corporate LAN</short>
  <interface name="eth1"/>
  <service name="dns"/>
  <service name="samba"/>
  <service name="nfs"/>
</zone>`,
};

interface ReviewRuleItem {
  ruleId: string;
  reason: string;
  originalSummary?: string;
  status: 'pending' | 'kept_disabled' | 'enabled' | 'deleted';
}

interface RuleEditDraft {
  action: 'pass' | 'block' | 'reject';
  source: string;
  destination: string;
  destinationPort: string;
  description: string;
}

export default function ImportPage() {
  const [selectedVendor, setSelectedVendor] = useState<FirewallVendor | 'auto'>('auto');
  const [detectedVendor, setDetectedVendor] = useState<FirewallVendor | null>(null);
  const [configInput, setConfigInput] = useState(SAMPLE_CONFIGS.pfsense);
  const [report, setReport] = useState<ImportReport | null>(null);
  const [ruleAnalysis, setRuleAnalysis] = useState<RuleAnalysisReport | null>(null);
  const [compiledNft, setCompiledNft] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isApplying, setIsApplying] = useState(false);
  const [applyResult, setApplyResult] = useState<string | null>(null);
  const [reviewItems, setReviewItems] = useState<ReviewRuleItem[]>([]);
  const [activeReviewIndex, setActiveReviewIndex] = useState(0);
  const [editDraft, setEditDraft] = useState<RuleEditDraft>({
    action: 'block',
    source: 'any',
    destination: 'any',
    destinationPort: 'any',
    description: '',
  });
  const fileInputRef = useRef<HTMLInputElement>(null);

  function loadDraftForRule(rules: any[], ruleId?: string) {
    if (!ruleId) return;
    const target = rules.find((r) => r.id === ruleId);
    if (!target) return;
    setEditDraft({
      action: target.action || 'block',
      source: target.source || 'any',
      destination: target.destination || 'any',
      destinationPort: target.destinationPort || 'any',
      description: (target.description || '').replace(/^\[REVIEW[^\]]*\]\s*/i, ''),
    });
  }

  function selectReviewStep(nextIndex: number, currentReport = report, items = reviewItems) {
    if (items.length === 0) return;
    const clamped = Math.max(0, Math.min(items.length - 1, nextIndex));
    setActiveReviewIndex(clamped);
    if (currentReport) {
      loadDraftForRule(currentReport.state.rules || [], items[clamped]?.ruleId);
    }
  }

  function handleSelectVendor(vendor: FirewallVendor | 'auto') {
    setSelectedVendor(vendor);
    if (vendor !== 'auto') {
      setConfigInput(SAMPLE_CONFIGS[vendor]);
      setDetectedVendor(vendor);
    }
  }

  function handleLoadSample() {
    const target = selectedVendor === 'auto' ? 'pfsense' : selectedVendor;
    setConfigInput(SAMPLE_CONFIGS[target]);
  }

  function handleFileUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      if (content) {
        setConfigInput(content);
        const auto = detectFirewallType(content);
        setDetectedVendor(auto);
      }
    };
    reader.readAsText(file);
  }

  function handleImport() {
    setError(null);
    setApplyResult(null);
    try {
      const targetVendor = selectedVendor === 'auto' ? undefined : selectedVendor;
      const res = importFirewallConfig(configInput, targetVendor);

      // Inspect res.reviewItems and res.state.rules for rules flagged for review
      const detectedReviewsMap = new Map<string, ReviewRuleItem>();
      const reportReviewItems = (res as any).reviewItems as Array<any> | undefined;
      if (Array.isArray(reportReviewItems)) {
        for (const item of reportReviewItems) {
          const rId = item.ruleId || item.id;
          if (rId) {
            detectedReviewsMap.set(rId, {
              ruleId: rId,
              reason:
                item.reason ||
                'Source config used a negated (NOT / !) match. Automatic positive conversion would invert your security policy, so Axonwall imported this rule disabled for your review.',
              originalSummary: item.originalMatch || item.originalSummary,
              status: 'pending',
            });
          }
        }
      }

      const rules = res.state.rules || [];
      for (const rule of rules) {
        if (detectedReviewsMap.has(rule.id)) continue;
        const desc = rule.description || '';
        const isDisabledReview =
          rule.enabled === false &&
          (desc.includes('[REVIEW') || /negat|invert/i.test(desc));
        const hasNegatedWarning = (res.warnings || []).some(
          (w) =>
            /negat|invert/i.test(w) &&
            desc &&
            w.toLowerCase().includes(desc.replace(/^\[REVIEW[^\]]*\]\s*/i, '').toLowerCase())
        );
        if (isDisabledReview || hasNegatedWarning) {
          rule.enabled = false;
          detectedReviewsMap.set(rule.id, {
            ruleId: rule.id,
            reason:
              'Source config used a negated (NOT / !) match. Automatic positive conversion would invert your security policy, so Axonwall imported this rule disabled for your review.',
            status: 'pending',
          });
        }
      }

      // Also detect XML <not/> or <not> blocks in raw source config if not yet flagged by parser
      if (detectedReviewsMap.size === 0 && /<not\s*\/?>/i.test(configInput)) {
        const ruleBlocks = configInput.match(/<rule>[\s\S]*?<\/rule>/gi) || [];
        for (const block of ruleBlocks) {
          if (/<not\s*\/?>/i.test(block)) {
            const descrMatch = block.match(/<descr>([\s\S]*?)<\/descr>/i);
            const rawDescr = descrMatch?.[1]?.trim();
            if (rawDescr) {
              const matchedRule = rules.find((r) =>
                (r.description || '').toLowerCase().includes(rawDescr.toLowerCase())
              );
              if (matchedRule && !detectedReviewsMap.has(matchedRule.id)) {
                matchedRule.enabled = false;
                if (!matchedRule.description?.includes('[REVIEW')) {
                  matchedRule.description = `[REVIEW: Negated Match] ${matchedRule.description}`;
                }
                detectedReviewsMap.set(matchedRule.id, {
                  ruleId: matchedRule.id,
                  reason:
                    'Source config used a negated (NOT / !) match. Automatic positive conversion would invert your security policy, so Axonwall imported this rule disabled for your review.',
                  status: 'pending',
                });
              }
            }
          }
        }
      }

      const nextReviewItems = Array.from(detectedReviewsMap.values());
      setReviewItems(nextReviewItems);
      setActiveReviewIndex(0);
      if (nextReviewItems.length > 0) {
        loadDraftForRule(rules, nextReviewItems[0]?.ruleId);
      }

      setReport(res);
      setDetectedVendor(res.vendor);

      const analysis = analyzeRuleShadowing(res.state.rules || []);
      setRuleAnalysis(analysis);

      const { nftScript } = compileNftables(res.state);
      setCompiledNft(nftScript);
    } catch (err: any) {
      setError(err?.message || 'Failed to parse configuration');
      setReport(null);
      setRuleAnalysis(null);
      setCompiledNft(null);
      setReviewItems([]);
    }
  }

  function advanceToNextReviewStep(updatedReport: ImportReport, updatedItems: ReviewRuleItem[], currentIdx: number) {
    // Prefer next pending item, otherwise next sequential item
    let nextIdx = currentIdx;
    for (let offset = 1; offset < updatedItems.length; offset++) {
      const candidate = (currentIdx + offset) % updatedItems.length;
      if (updatedItems[candidate]?.status === 'pending') {
        nextIdx = candidate;
        break;
      }
    }
    if (nextIdx === currentIdx && currentIdx < updatedItems.length - 1) {
      nextIdx = currentIdx + 1;
    }
    selectReviewStep(nextIdx, updatedReport, updatedItems);
  }

  function recomputeReportAndNft(updatedReport: ImportReport) {
    setReport(updatedReport);
    const analysis = analyzeRuleShadowing(updatedReport.state.rules || []);
    setRuleAnalysis(analysis);
    const { nftScript } = compileNftables(updatedReport.state);
    setCompiledNft(nftScript);
  }

  function handleKeepRuleDisabled() {
    if (!report || reviewItems.length === 0) return;
    const activeItem = reviewItems[activeReviewIndex];
    if (!activeItem) return;

    const updatedRules = (report.state.rules || []).map((r) =>
      r.id === activeItem.ruleId
        ? {
            ...r,
            enabled: false,
            action: editDraft.action,
            source: editDraft.source.trim() || 'any',
            destination: editDraft.destination.trim() || 'any',
            destinationPort:
              editDraft.destinationPort.trim() && editDraft.destinationPort.trim() !== 'any'
                ? editDraft.destinationPort.trim()
                : undefined,
            description: editDraft.description.trim() || r.description,
          }
        : r
    );

    const updatedReport: ImportReport = {
      ...report,
      state: {
        ...report.state,
        rules: updatedRules,
      },
    };

    const updatedItems = reviewItems.map((item, idx) =>
      idx === activeReviewIndex ? { ...item, status: 'kept_disabled' as const } : item
    );

    setReviewItems(updatedItems);
    recomputeReportAndNft(updatedReport);
    advanceToNextReviewStep(updatedReport, updatedItems, activeReviewIndex);
  }

  function handleSaveAndEnableRule() {
    if (!report || reviewItems.length === 0) return;
    const activeItem = reviewItems[activeReviewIndex];
    if (!activeItem) return;

    const cleanDescription = editDraft.description
      .replace(/^\[REVIEW[^\]]*\]\s*/i, '')
      .trim();

    const updatedRules = (report.state.rules || []).map((r) =>
      r.id === activeItem.ruleId
        ? {
            ...r,
            enabled: true,
            action: editDraft.action,
            source: editDraft.source.trim() || 'any',
            destination: editDraft.destination.trim() || 'any',
            destinationPort:
              editDraft.destinationPort.trim() && editDraft.destinationPort.trim() !== 'any'
                ? editDraft.destinationPort.trim()
                : undefined,
            description: cleanDescription || 'Reviewed Rule',
          }
        : r
    );

    const updatedReport: ImportReport = {
      ...report,
      state: {
        ...report.state,
        rules: updatedRules,
      },
    };

    const updatedItems = reviewItems.map((item, idx) =>
      idx === activeReviewIndex ? { ...item, status: 'enabled' as const } : item
    );

    setReviewItems(updatedItems);
    recomputeReportAndNft(updatedReport);
    advanceToNextReviewStep(updatedReport, updatedItems, activeReviewIndex);
  }

  function handleDeleteReviewRule() {
    if (!report || reviewItems.length === 0) return;
    const activeItem = reviewItems[activeReviewIndex];
    if (!activeItem) return;

    const updatedRules = (report.state.rules || []).filter((r) => r.id !== activeItem.ruleId);

    const updatedReport: ImportReport = {
      ...report,
      rulesCount: updatedRules.length,
      state: {
        ...report.state,
        rules: updatedRules,
      },
    };

    const updatedItems = reviewItems.map((item, idx) =>
      idx === activeReviewIndex ? { ...item, status: 'deleted' as const } : item
    );

    setReviewItems(updatedItems);
    recomputeReportAndNft(updatedReport);
    advanceToNextReviewStep(updatedReport, updatedItems, activeReviewIndex);
  }

  function handleDownloadJson() {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report.state, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `axonwall-state-${report.vendor}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function handleDownloadNft() {
    if (!compiledNft) return;
    const blob = new Blob([compiledNft], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `axonwall-ruleset-${report?.vendor || 'migrated'}.nft`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  async function handleApplyLive() {
    if (!report) return;
    const pendingReviewsCount = reviewItems.filter((item) => item.status === 'pending').length;
    if (pendingReviewsCount > 0) {
      const proceedUnreviewed = window.confirm(
        `Warning: ${pendingReviewsCount} flagged rule(s) with negated/inverted matches have not yet been reviewed in the Guided Rule Review Walkthrough and are currently disabled.\n\nDo you still want to proceed with applying this configuration?`
      );
      if (!proceedUnreviewed) return;
    }

    const confirm = window.confirm(
      `Apply this converted configuration directly to the live Axonwall system?\n\nSafety rollback is automatically armed for 120 seconds.`
    );
    if (!confirm) return;

    setIsApplying(true);
    setApplyResult(null);
    try {
      const res = await fetch('/api/v1/apply', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          state: report.state,
          confirmTimeoutSeconds: 120,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to apply configuration to live firewall');
      }

      setApplyResult(
        'Configuration applied successfully! Watchdog rollback is armed for 120s.'
      );
    } catch (err: any) {
      setError(err.message || 'Error applying configuration');
    } finally {
      setIsApplying(false);
    }
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
          <Layers className="w-6 h-6 text-emerald-400" />
          <span>Firewall Migration Studio</span>
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Import and translate existing firewall configurations (pfSense, OPNsense, VyOS / EdgeOS, MikroTik RouterOS, Cisco ASA, Linux iptables, and Linux firewalld) directly into Axonwall DesiredState and production Linux nftables.
        </p>
      </div>

      {/* Vendor Selector Bar */}
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 pb-4">
        {VENDOR_OPTIONS.map((vendor) => {
          const isActive = selectedVendor === vendor.id;
          return (
            <button
              key={vendor.id}
              type="button"
              onClick={() => handleSelectVendor(vendor.id)}
              className={`px-3 py-2 rounded-lg text-xs font-medium flex items-center gap-2 transition cursor-pointer ${
                isActive
                  ? 'bg-emerald-600/20 text-emerald-400 border border-emerald-500/40 shadow-sm'
                  : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <span>{vendor.label}</span>
              <span
                className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${
                  isActive ? 'bg-emerald-500/20 text-emerald-300' : 'bg-slate-800 text-slate-500'
                }`}
              >
                {vendor.badge}
              </span>
            </button>
          );
        })}
      </div>

      {/* Main Conversion Split View */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Input Configuration Editor */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <UploadCloud className="w-4 h-4 text-emerald-400" />
              <span className="text-sm font-semibold text-white">Source Configuration</span>
              {detectedVendor && (
                <span className="text-[11px] px-2 py-0.5 rounded-full bg-cyan-950 border border-cyan-800/60 text-cyan-400 font-mono">
                  {detectedVendor}
                </span>
              )}
            </div>

            <div className="flex items-center gap-2">
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileUpload}
                className="hidden"
                accept=".xml,.boot,.rsc,.v4,.conf,.txt"
              />
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1.5 rounded-lg text-xs font-medium transition cursor-pointer"
                title="Upload config file from disk"
              >
                Upload File
              </button>
              <button
                type="button"
                onClick={handleLoadSample}
                className="bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1.5 rounded-lg text-xs font-medium transition cursor-pointer"
                title="Load sample configuration for current vendor"
              >
                Load Sample
              </button>
              <button
                type="button"
                onClick={handleImport}
                className="bg-emerald-600 hover:bg-emerald-500 text-white px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer shadow"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Parse & Convert</span>
              </button>
            </div>
          </div>

          <textarea
            value={configInput}
            onChange={(e) => {
              setConfigInput(e.target.value);
              if (selectedVendor === 'auto') {
                setDetectedVendor(detectFirewallType(e.target.value));
              }
            }}
            rows={16}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-emerald-500 leading-relaxed resize-y"
            placeholder="Paste firewall configuration (XML, config.boot, RouterOS script, or iptables-save)..."
          />

          {error && (
            <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-xs text-red-400 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold block">Conversion Error</span>
                <span>{error}</span>
              </div>
            </div>
          )}

          {applyResult && (
            <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-xs text-emerald-300 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
              <span>{applyResult}</span>
            </div>
          )}
        </div>

        {/* Migration Report & Metrics */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-sm font-semibold text-white flex items-center gap-2">
              <FileText className="w-4 h-4 text-cyan-400" />
              <span>Translation & Compatibility Summary</span>
            </span>
            {report && (
              <span className="text-[11px] px-2 py-0.5 rounded-full bg-emerald-950 border border-emerald-800/60 text-emerald-400 font-mono">
                {report.vendor.toUpperCase()} {report.version ? `v${report.version}` : ''}
              </span>
            )}
          </div>

          {report ? (
            <div className="space-y-4">
              <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg flex items-center gap-2 text-xs text-emerald-300">
                <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
                <span>
                  Successfully translated {report.vendor.toUpperCase()} configuration into modern Axonwall DesiredState!
                </span>
              </div>

              {/* Counters Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                  <span className="text-slate-400 block font-sans text-[11px]">Interfaces</span>
                  <span className="text-base font-bold text-white">{report.interfacesCount}</span>
                </div>
                <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                  <span className="text-slate-400 block font-sans text-[11px]">VLANs</span>
                  <span className="text-base font-bold text-cyan-400">{report.vlansCount}</span>
                </div>
                <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                  <span className="text-slate-400 block font-sans text-[11px]">Aliases / Groups</span>
                  <span className="text-base font-bold text-white">{report.aliasesCount}</span>
                </div>
                <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                  <span className="text-slate-400 block font-sans text-[11px]">Filter Rules</span>
                  <span className="text-base font-bold text-emerald-400">{report.rulesCount}</span>
                </div>
                <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                  <span className="text-slate-400 block font-sans text-[11px]">NAT Rules</span>
                  <span className="text-base font-bold text-amber-400">{report.natRulesCount}</span>
                </div>
                <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                  <span className="text-slate-400 block font-sans text-[11px]">DHCP Pools</span>
                  <span className="text-base font-bold text-white">{report.dhcpSubnetsCount}</span>
                </div>
                <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                  <span className="text-slate-400 block font-sans text-[11px]">DNS Overrides</span>
                  <span className="text-base font-bold text-white">{report.dnsOverridesCount}</span>
                </div>
                <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                  <span className="text-slate-400 block font-sans text-[11px]">Static Routes</span>
                  <span className="text-base font-bold text-white">{report.routesCount}</span>
                </div>
              </div>

              {/* Rule Optimization & Shadowing Analysis */}
              {ruleAnalysis && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-white flex items-center gap-1.5">
                      <Layers className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Rule Analysis & Shadow Detection</span>
                    </span>
                    <span
                      className={`text-[11px] font-mono px-2 py-0.5 rounded-full ${
                        ruleAnalysis.issues.length > 0
                          ? 'bg-amber-950 text-amber-300 border border-amber-800/60'
                          : 'bg-emerald-950 text-emerald-400 border border-emerald-800/60'
                      }`}
                    >
                      {ruleAnalysis.issues.length > 0
                        ? `${ruleAnalysis.issues.length} Optimization Notice${ruleAnalysis.issues.length > 1 ? 's' : ''}`
                        : 'All Rules Clean'}
                    </span>
                  </div>

                  {ruleAnalysis.issues.length > 0 ? (
                    <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 space-y-2 max-h-48 overflow-y-auto text-xs">
                      {ruleAnalysis.issues.map((issue, idx) => (
                        <div
                          key={idx}
                          className="p-2 rounded bg-slate-900 border border-slate-800 space-y-1"
                        >
                          <div className="flex items-center gap-2">
                            <span
                              className={`text-[10px] uppercase font-bold px-1.5 py-0.5 rounded font-mono ${
                                issue.type === 'shadowed'
                                  ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                                  : issue.type === 'redundant'
                                  ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                                  : 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                              }`}
                            >
                              {issue.type}
                            </span>
                            <span className="text-slate-300 font-medium">
                              Rule #{issue.ruleIndex}
                            </span>
                            <span className="text-slate-500">
                              (shadowed by #{issue.shadowedByIndex})
                            </span>
                          </div>
                          <p className="text-slate-400 text-[11px]">{issue.description}</p>
                          <p className="text-emerald-400/90 text-[11px] font-mono">
                            ↳ Suggestion: {issue.suggestion}
                          </p>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-400 flex items-center gap-2">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                      <span>Zero shadowed, redundant, or dead rules detected in ruleset.</span>
                    </div>
                  )}
                </div>
              )}

              {/* Warnings List */}
              {report.warnings && report.warnings.length > 0 && (
                <div className="space-y-2">
                  <span className="text-xs font-semibold text-amber-400 flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>Vendor Compatibility Notices ({report.warnings.length})</span>
                  </span>
                  <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-3 space-y-1.5 max-h-36 overflow-y-auto text-xs text-amber-300">
                    {report.warnings.map((warn, idx) => (
                      <div key={idx} className="flex items-start gap-2">
                        <span className="text-amber-500 select-none">•</span>
                        <span>{warn}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Action Buttons */}
              <div className="pt-2 flex flex-wrap items-center gap-3">
                <button
                  type="button"
                  onClick={handleDownloadJson}
                  className="bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download State JSON</span>
                </button>
                <button
                  type="button"
                  onClick={handleDownloadNft}
                  className="bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download nftables Script</span>
                </button>
                <button
                  type="button"
                  onClick={handleApplyLive}
                  disabled={isApplying}
                  className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer ml-auto shadow"
                >
                  {isApplying ? (
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <Check className="w-3.5 h-3.5" />
                  )}
                  <span>{isApplying ? 'Applying...' : 'Apply to Live Firewall'}</span>
                </button>
              </div>
            </div>
          ) : (
            <div className="h-64 flex flex-col items-center justify-center text-slate-500 text-xs text-center p-6">
              <FileCode className="w-12 h-12 text-slate-700 mb-3" />
              <span className="font-medium text-slate-400">Ready to Parse Configuration</span>
              <span className="mt-1 text-slate-600 max-w-sm">
                Select your source firewall vendor or use Auto-Detect, paste your configuration, and click "Parse & Convert".
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Guided Rule Review Walkthrough Card */}
      {report && reviewItems.length > 0 && (() => {
        const activeItem = reviewItems[activeReviewIndex] || reviewItems[0];
        const currentRule = (report.state.rules || []).find((r) => r.id === activeItem?.ruleId);
        const resolvedCount = reviewItems.filter((i) => i.status !== 'pending').length;
        const progressPct = Math.round((resolvedCount / reviewItems.length) * 100);

        return (
          <div className="bg-amber-950/20 border border-amber-500/40 rounded-xl p-5 space-y-4 shadow-lg">
            {/* Walkthrough Header & Step Progress */}
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-amber-500/20 pb-3.5">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-lg bg-amber-500/20 border border-amber-500/30 text-amber-400">
                  <ShieldAlert className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-sm font-bold text-white">
                      Guided Rule Review Walkthrough
                    </h2>
                    <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-amber-500/20 border border-amber-500/40 text-amber-300">
                      Reviewing Rule {activeReviewIndex + 1} of {reviewItems.length}
                    </span>
                    <span
                      className={`text-[11px] font-mono px-2 py-0.5 rounded-full border ${
                        resolvedCount === reviewItems.length
                          ? 'bg-emerald-950/80 border-emerald-500/40 text-emerald-300'
                          : 'bg-slate-900 border-slate-700 text-slate-300'
                      }`}
                    >
                      {resolvedCount} of {reviewItems.length} Resolved
                    </span>
                  </div>
                  <p className="text-xs text-amber-200/80 mt-0.5">
                    Step through rules that used negated or inverted matches in your legacy firewall before enabling them in production.
                  </p>
                </div>
              </div>

              {/* Previous / Next Navigation */}
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => selectReviewStep(activeReviewIndex - 1)}
                  disabled={activeReviewIndex <= 0}
                  className="bg-slate-900 hover:bg-slate-800 disabled:opacity-40 text-slate-200 border border-slate-700 px-2.5 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1 transition cursor-pointer"
                >
                  <ChevronLeft className="w-3.5 h-3.5" />
                  <span>Previous</span>
                </button>
                <button
                  type="button"
                  onClick={() => selectReviewStep(activeReviewIndex + 1)}
                  disabled={activeReviewIndex >= reviewItems.length - 1}
                  className="bg-slate-900 hover:bg-slate-800 disabled:opacity-40 text-slate-200 border border-slate-700 px-2.5 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1 transition cursor-pointer"
                >
                  <span>Next</span>
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {/* Progress Bar & Step Pills */}
            <div className="space-y-2">
              <div className="w-full h-2 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
                <div
                  className="h-full bg-gradient-to-r from-amber-500 to-emerald-500 transition-all duration-300"
                  style={{ width: `${Math.max(progressPct, 6)}%` }}
                />
              </div>
              <div className="flex flex-wrap items-center gap-1.5">
                {reviewItems.map((item, idx) => {
                  const isCurrent = idx === activeReviewIndex;
                  const statusBadgeColor =
                    item.status === 'enabled'
                      ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                      : item.status === 'kept_disabled'
                      ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40'
                      : item.status === 'deleted'
                      ? 'bg-red-500/20 text-red-300 border-red-500/40'
                      : 'bg-slate-900 text-amber-300 border-amber-500/30';
                  return (
                    <button
                      key={item.ruleId}
                      type="button"
                      onClick={() => selectReviewStep(idx)}
                      className={`px-2.5 py-1 rounded-md text-[11px] font-mono border transition cursor-pointer ${statusBadgeColor} ${
                        isCurrent ? 'ring-2 ring-amber-400/70 font-bold' : 'opacity-80 hover:opacity-100'
                      }`}
                    >
                      Rule #{idx + 1}:{' '}
                      {item.status === 'pending'
                        ? 'Needs Review'
                        : item.status === 'kept_disabled'
                        ? 'Kept Disabled'
                        : item.status === 'enabled'
                        ? 'Enabled'
                        : 'Deleted'}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Policy Inversion Explanation Banner */}
            <div className="p-3 rounded-lg bg-slate-950/90 border border-amber-500/30 text-xs text-amber-200 space-y-1">
              <div className="font-semibold text-amber-300 flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 shrink-0" />
                <span>Why was this rule imported with enabled: false?</span>
              </div>
              <p className="text-slate-300 leading-relaxed">
                Source config used a negated (<code className="text-amber-300">NOT</code> / <code className="text-amber-300">!</code>) match. Automatic positive conversion would invert your security policy, so Axonwall imported this rule disabled for your review.
              </p>
            </div>

            {/* Current Rule Context & Inline Editor */}
            {activeItem?.status === 'deleted' || !currentRule ? (
              <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400 flex items-center justify-between">
                <span>This rule was removed from the imported ruleset during review.</span>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/30">
                  Deleted
                </span>
              </div>
            ) : (
              <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 space-y-4">
                {/* Context Summary Row */}
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs border-b border-slate-800/80 pb-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-slate-400">Interface:</span>
                    <span className="font-mono px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-cyan-300">
                      {currentRule.interface}
                    </span>
                    <span className="text-slate-400">Protocol:</span>
                    <span className="font-mono px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-200 uppercase">
                      {currentRule.protocol}
                    </span>
                    <span className="text-slate-400">Current State:</span>
                    <span
                      className={`font-mono px-2 py-0.5 rounded border ${
                        currentRule.enabled
                          ? 'bg-emerald-950 border-emerald-700 text-emerald-300'
                          : 'bg-amber-950 border-amber-700 text-amber-300'
                      }`}
                    >
                      {currentRule.enabled ? 'ENABLED' : 'DISABLED (SAFE)'}
                    </span>
                  </div>
                  <span className="text-[11px] font-mono text-slate-500">
                    ID: {currentRule.id}
                  </span>
                </div>

                {/* Inline Editable Fields */}
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 text-xs">
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">Action</label>
                    <select
                      value={editDraft.action}
                      onChange={(e) =>
                        setEditDraft({
                          ...editDraft,
                          action: e.target.value as 'pass' | 'block' | 'reject',
                        })
                      }
                      className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-white font-mono focus:outline-none focus:ring-1 focus:ring-amber-500"
                    >
                      <option value="block">block</option>
                      <option value="reject">reject</option>
                      <option value="pass">pass</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">
                      Source (CIDR / Alias / any)
                    </label>
                    <input
                      type="text"
                      value={editDraft.source}
                      onChange={(e) => setEditDraft({ ...editDraft, source: e.target.value })}
                      className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-white font-mono focus:outline-none focus:ring-1 focus:ring-amber-500"
                      placeholder="any or 192.168.10.0/24"
                    />
                  </div>

                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">
                      Destination (CIDR / Alias / any)
                    </label>
                    <input
                      type="text"
                      value={editDraft.destination}
                      onChange={(e) => setEditDraft({ ...editDraft, destination: e.target.value })}
                      className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-white font-mono focus:outline-none focus:ring-1 focus:ring-amber-500"
                      placeholder="e.g. 10.0.0.0/8 or Alias"
                    />
                  </div>

                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">
                      Destination Port
                    </label>
                    <input
                      type="text"
                      value={editDraft.destinationPort}
                      onChange={(e) =>
                        setEditDraft({ ...editDraft, destinationPort: e.target.value })
                      }
                      className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-white font-mono focus:outline-none focus:ring-1 focus:ring-amber-500"
                      placeholder="any or 443"
                    />
                  </div>

                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">
                      Rule Description
                    </label>
                    <input
                      type="text"
                      value={editDraft.description}
                      onChange={(e) => setEditDraft({ ...editDraft, description: e.target.value })}
                      className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-white focus:outline-none focus:ring-1 focus:ring-amber-500"
                      placeholder="Rule description"
                    />
                  </div>
                </div>

                {/* 3 Resolution Action Buttons */}
                <div className="flex flex-wrap items-center justify-end gap-2.5 pt-2 border-t border-slate-800/80">
                  <button
                    type="button"
                    onClick={handleKeepRuleDisabled}
                    className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer"
                  >
                    <Lock className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Keep Disabled (Safe)</span>
                  </button>

                  <button
                    type="button"
                    onClick={handleSaveAndEnableRule}
                    className="bg-emerald-600 hover:bg-emerald-500 text-white px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer shadow"
                  >
                    <Check className="w-3.5 h-3.5" />
                    <span>Save Edits &amp; Enable Rule</span>
                  </button>

                  <button
                    type="button"
                    onClick={handleDeleteReviewRule}
                    className="bg-red-950/70 hover:bg-red-900/70 text-red-300 border border-red-800/60 px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span>Delete Rule</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        );
      })()}

      {/* Generated nftables Ruleset Preview */}
      {compiledNft && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-sm font-semibold text-white flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-400" />
              <span>Converted Linux nftables Ruleset (table inet axonwall)</span>
            </span>
            <span className="text-xs text-slate-400 font-mono">
              Direct Linux kernel representation
            </span>
          </div>
          <pre className="bg-slate-950 border border-slate-800/80 rounded-lg p-4 font-mono text-xs text-slate-300 overflow-x-auto max-h-96 leading-relaxed">
            {compiledNft}
          </pre>
        </div>
      )}
    </div>
  );
}
