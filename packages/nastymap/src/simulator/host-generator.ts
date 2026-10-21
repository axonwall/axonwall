/**
 * NastyMap Dynamic Host & Scenario Generator
 * Generates realistic local network topologies with normal phones, laptops, and IoT devices,
 * plus configurable stealthy malicious threats for cybersecurity threat hunting simulations.
 */

import type { NmapHost, NmapPort, NmapRun, NmapOs, NmapAddress, NmapHostname, NmapScript } from '../types/nmap';

export type ThreatCategory =
  | 'metasploit_c2'
  | 'cryptominer'
  | 'ransomware_pivot'
  | 'arp_spoofer'
  | 'backdoor_shell';

export interface MaliciousThreatInfo {
  threatId: string;
  threatType: ThreatCategory;
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  description: string;
  detectionClues: string[];
  remediation: string;
  cve?: string;
  isNeutralized?: boolean;
}

export interface ScenarioGeneratorOptions {
  subnet?: string; // e.g. "192.168.1.0/24"
  gatewayIp?: string; // default "192.168.1.1"
  totalHosts?: number; // default 20
  threatCount?: number; // number of malicious hosts (default 2)
  includeSmartphones?: boolean; // default true
  includeLaptops?: boolean; // default true
  includeIoT?: boolean; // default true
  gameMode?: boolean; // default true
  difficulty?: 'easy' | 'medium' | 'hard';
  seed?: number;
}

// Random helper with deterministic-friendly structure
function randomElement<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function generateMac(vendorPrefix: string): string {
  const hex = '0123456789ABCDEF';
  let mac = vendorPrefix;
  while (mac.replace(/:/g, '').length < 12) {
    mac += `:${hex[Math.floor(Math.random() * 16)]}${hex[Math.floor(Math.random() * 16)]}`;
  }
  return mac;
}

// ─────────────────────────────────────────────────────────────────────────────
// Normal Device Templates
// ─────────────────────────────────────────────────────────────────────────────

interface DeviceArchetype {
  category: 'phone' | 'laptop' | 'iot' | 'infrastructure';
  names: string[];
  osFamily: string;
  osName: string;
  deviceType: string;
  vendor: string;
  macPrefix: string;
  ports: () => NmapPort[];
}

const PHONE_ARCHETYPES: DeviceArchetype[] = [
  {
    category: 'phone',
    names: ["Alex's iPhone 15", "Sarah's iPhone 14 Pro", "Marcus-iPhone", "Work-iPhone-13", "iPad-Air-Studio"],
    osFamily: 'Apple iOS',
    osName: 'Apple iOS 17.4 (Darwin 23.4.0)',
    deviceType: 'phone',
    vendor: 'Apple Inc.',
    macPrefix: 'F0:18:98',
    ports: () => [
      {
        portid: 5000,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'airplay', product: 'Apple AirPlay audio service', version: '2.0' },
      },
      {
        portid: 7000,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'airplay-mirror', product: 'Apple AirPlay screen mirror' },
      },
    ],
  },
  {
    category: 'phone',
    names: ["David's Galaxy S24", "Samsung-S23-Ultra", "Galaxy-Fold5", "Android-Dev-Pixel8", "Pixel-8-Pro"],
    osFamily: 'Android',
    osName: 'Android 14 (Linux 6.1)',
    deviceType: 'phone',
    vendor: 'Samsung Electronics',
    macPrefix: '50:01:D9',
    ports: () => [
      {
        portid: 8008,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'googlecast', product: 'Google Cast API' },
      },
    ],
  },
];

const LAPTOP_ARCHETYPES: DeviceArchetype[] = [
  {
    category: 'laptop',
    names: ['macbook-pro-m3.local', 'studio-mac-mini.local', 'MBP-Engineering.lan', 'design-macbook.local'],
    osFamily: 'macOS',
    osName: 'Apple macOS Sonoma 14.5',
    deviceType: 'workstation',
    vendor: 'Apple Inc.',
    macPrefix: 'AC:BC:32',
    ports: () => [
      {
        portid: 22,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'ssh', product: 'OpenSSH', version: '9.6p1', extrainfo: 'Apple_SecureTransport' },
      },
      {
        portid: 5900,
        protocol: 'tcp',
        state: 'closed',
        service: { name: 'vnc', product: 'Apple Remote Desktop VNC' },
      },
      {
        portid: 3000,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'http', product: 'Next.js Dev Server / Node.js' },
      },
    ],
  },
  {
    category: 'laptop',
    names: ['THINKPAD-X1-UBUNTU', 'dev-box-linux', 'ubuntu-laptop.lan', 'dell-precision-dev'],
    osFamily: 'Linux',
    osName: 'Ubuntu Linux 24.04 LTS (Kernel 6.8)',
    deviceType: 'workstation',
    vendor: 'Lenovo',
    macPrefix: '54:E1:AD',
    ports: () => [
      {
        portid: 22,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'ssh', product: 'OpenSSH', version: '9.6p1 Ubuntu 3ubuntu13' },
      },
      {
        portid: 8080,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'http-proxy', product: 'Vite / Webpack Development Server' },
      },
    ],
  },
  {
    category: 'laptop',
    names: ['DESKTOP-ACCOUNTING', 'LAPTOP-OFFICE-03', 'WIN11-WORKSTATION', 'DELL-OPTIPLEX-08'],
    osFamily: 'Windows',
    osName: 'Microsoft Windows 11 Pro 23H2',
    deviceType: 'workstation',
    vendor: 'Dell Inc.',
    macPrefix: '74:86:7A',
    ports: () => [
      {
        portid: 135,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'msrpc', product: 'Microsoft Windows RPC' },
      },
      {
        portid: 445,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'microsoft-ds', product: 'Windows 11 Workstation SMB service' },
      },
      {
        portid: 3389,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'ms-wbt-server', product: 'Microsoft Terminal Services RDP' },
      },
    ],
  },
];

const IOT_ARCHETYPES: DeviceArchetype[] = [
  {
    category: 'iot',
    names: ['HP-LaserJet-Pro-M404.lan', 'Printer-Color-Office.local', 'Canon-ImageRUNNER-ADV'],
    osFamily: 'Embedded',
    osName: 'HP JetDirect Embedded Firmware',
    deviceType: 'printer',
    vendor: 'HP Inc.',
    macPrefix: '00:9C:02',
    ports: () => [
      {
        portid: 80,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'http', product: 'HP Web Jetadmin UI', version: '4.2' },
      },
      {
        portid: 631,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'ipp', product: 'Internet Printing Protocol 2.0' },
      },
      {
        portid: 9100,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'jetdirect', product: 'HP Raw Print Port 9100' },
      },
    ],
  },
  {
    category: 'iot',
    names: ['Synology-DS920-Vault.lan', 'QNAP-Storage-Hub.local', 'Office-NAS-Backup'],
    osFamily: 'Linux',
    osName: 'Synology DSM 7.2 (Linux 4.4)',
    deviceType: 'storage',
    vendor: 'Synology Inc.',
    macPrefix: '00:11:32',
    ports: () => [
      {
        portid: 22,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'ssh', product: 'OpenSSH Synology' },
      },
      {
        portid: 445,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'microsoft-ds', product: 'Samba 4.15 (Synology File Service)' },
      },
      {
        portid: 5000,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'http', product: 'Synology DiskStation Manager Web GUI' },
      },
      {
        portid: 5001,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'https', product: 'Synology DiskStation Manager SSL' },
      },
    ],
  },
  {
    category: 'iot',
    names: ['LivingRoom-LG-OLED.lan', 'Samsung-SmartTV-Conference', 'Sony-Bravia-Office'],
    osFamily: 'Embedded',
    osName: 'LG webOS TV 23',
    deviceType: 'smart_tv',
    vendor: 'LG Electronics',
    macPrefix: '10:F9:6F',
    ports: () => [
      {
        portid: 8080,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'http', product: 'LG TV Connect API' },
      },
      {
        portid: 8008,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'dial', product: 'DIAL Multiscreen protocol' },
      },
    ],
  },
  {
    category: 'iot',
    names: ['Ring-Doorbell-Cam.lan', 'Hallway-Security-Cam-01', 'Nest-Cam-Outdoor'],
    osFamily: 'Linux',
    osName: 'Embedded Linux 4.9 (Camera Firmware)',
    deviceType: 'camera',
    vendor: 'Ring Inc.',
    macPrefix: '9C:76:13',
    ports: () => [
      {
        portid: 80,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'http', product: 'GoAhead WebServer' },
      },
      {
        portid: 554,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'rtsp', product: 'Real Time Streaming Protocol H.264 video' },
      },
    ],
  },
  {
    category: 'iot',
    names: ['Sonos-Era300.lan', 'Sonos-Soundbar-Lounge', 'Office-Background-Sonos'],
    osFamily: 'Linux',
    osName: 'Sonos OS Linux',
    deviceType: 'speaker',
    vendor: 'Sonos Inc.',
    macPrefix: '48:A6:B8',
    ports: () => [
      {
        portid: 1400,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'http', product: 'Sonos Control API' },
      },
    ],
  },
  {
    category: 'iot',
    names: ['Hue-Bridge-Lighting.lan', 'Philips-Hue-V2', 'SmartThings-Hub'],
    osFamily: 'Embedded',
    osName: 'Zigbee Gateway OS',
    deviceType: 'iot_hub',
    vendor: 'Philips Lighting',
    macPrefix: 'EC:B5:FA',
    ports: () => [
      {
        portid: 80,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'http', product: 'Philips Hue Bridge REST API' },
      },
      {
        portid: 443,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'https', product: 'Philips Hue Bridge SSL' },
      },
    ],
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// Malicious Threat Generator (The targets to hunt!)
// ─────────────────────────────────────────────────────────────────────────────

interface ThreatBlueprint {
  threatType: ThreatCategory;
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  hostname: string;
  vendor: string;
  macPrefix: string;
  osFamily: string;
  osName: string;
  deviceType: string;
  description: string;
  detectionClues: string[];
  remediation: string;
  cve?: string;
  generatePorts: () => NmapPort[];
  generateScripts: () => NmapScript[];
}

const MALICIOUS_THREAT_BLUEPRINTS: ThreatBlueprint[] = [
  {
    threatType: 'metasploit_c2',
    name: 'Rogue Pentest Drop Box (Metasploit Shell)',
    severity: 'CRITICAL',
    hostname: 'print-server-hp2.lan', // Disguised hostname!
    vendor: 'Raspberry Pi Foundation',
    macPrefix: 'B8:27:EB',
    osFamily: 'Linux',
    osName: 'Kali Linux 2024.2 (Drop Pi)',
    deviceType: 'rogue_device',
    description: 'An unauthorized hardware implant running a persistent Metasploit Meterpreter reverse TCP connection to a malicious command & control server.',
    detectionClues: [
      'Port 4444 open (Default Metasploit payload listener)',
      'Port 1337 open with raw backdoor shell prompt',
      'Raspberry Pi MAC vendor masquerading with a printer hostname (print-server-hp2)',
      'NSE payload script shows outbound tunnel to external IP',
    ],
    remediation: 'Physically locate the rogue Raspberry Pi device, disconnect from the RJ45 ethernet switch port, and quarantine MAC address on the managed switch.',
    generatePorts: () => [
      {
        portid: 2222,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'ssh', product: 'Dropbear sshd', version: '2022.83' },
      },
      {
        portid: 1337,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'waste', product: 'Backdoor interactive root shell' },
      },
      {
        portid: 4444,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'krb524', product: 'Metasploit Meterpreter Reverse TCP' },
        scripts: [
          {
            id: 'metasploit-payload',
            output: 'VULNERABLE / ACTIVE: Reverse TCP shell active to external C2 (198.51.100.42:4444). Session PID 4812.',
          },
        ],
      },
    ],
    generateScripts: () => [
      {
        id: 'rogue-detector',
        output: 'SUSPICIOUS: Linux host claiming HP LaserJet identity without printer daemon.',
      },
    ],
  },
  {
    threatType: 'cryptominer',
    name: 'Compromised IoT Camera (Monero Cryptominer)',
    severity: 'HIGH',
    hostname: 'cam-breakroom-02.lan',
    vendor: 'Shenzhen Bilian Electronic',
    macPrefix: '00:1E:E3',
    osFamily: 'Linux',
    osName: 'BusyBox Embedded Linux (Infected)',
    deviceType: 'camera',
    description: 'A hallway IoT camera compromised via default credentials, running an unthrottled Monero XMRig cryptominer causing network congestion and 99% CPU load.',
    detectionClues: [
      'Port 3333 open running Stratum mining pool protocol',
      'Abnormally high round-trip latency (> 60ms) due to sustained 99.8% CPU mining load',
      'GoAhead web server on port 80 has outdated unauthenticated backdoor',
    ],
    remediation: 'Power-cycle camera into recovery mode, change factory default credentials, update firmware to vendor patch, and block outbound mining port 3333 on the firewall.',
    generatePorts: () => [
      {
        portid: 80,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'http', product: 'GoAhead WebServer', version: '2.1.8 (Vulnerable)' },
      },
      {
        portid: 554,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'rtsp', product: 'RTSP H.264 Stream' },
      },
      {
        portid: 3333,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'dec-notes', product: 'XMRig Monero Stratum Miner Protocol' },
        scripts: [
          {
            id: 'crypto-mining-check',
            output: 'ALERT: Monero Stratum protocol detected. Miner: xmrig/6.20.0, Pool: stratum+tcp://pool.minexmr.com:3333, Hashrate: 1.2 KH/s',
          },
        ],
      },
    ],
    generateScripts: () => [
      {
        id: 'cpu-stress-audit',
        output: 'Heavy packet jitter observed; device responsive ping delay exceeds normal baseline by 800%.',
      },
    ],
  },
  {
    threatType: 'ransomware_pivot',
    name: 'Compromised PC (Cobalt Strike C2 / Ransomware Stager)',
    severity: 'CRITICAL',
    hostname: 'DESKTOP-PAYROLL-01',
    vendor: 'Dell Inc.',
    macPrefix: '74:86:7A',
    osFamily: 'Windows',
    osName: 'Microsoft Windows 10 Pro (Compromised)',
    deviceType: 'workstation',
    cve: 'CVE-2017-0144',
    description: 'An internal payroll workstation compromised through phishing, exhibiting Cobalt Strike HTTPS beaconing and unpatched SMBv1 EternalBlue vulnerability.',
    detectionClues: [
      'Port 8443 open with malleable Cobalt Strike HTTPS C2 beacon listener',
      'Port 445 SMBv1 responds to MS17-010 EternalBlue vulnerability check',
      'Unusual outbound HTTPS beaconing pattern every 60 seconds with jitter',
    ],
    remediation: 'Immediately isolate host from the VLAN, preserve memory dump for digital forensics, disable SMBv1, and reimage the workstation.',
    generatePorts: () => [
      {
        portid: 135,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'msrpc', product: 'Microsoft Windows RPC' },
      },
      {
        portid: 445,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'microsoft-ds', product: 'Windows SMBv1 (MS17-010 Vulnerable)' },
        scripts: [
          {
            id: 'smb-vuln-ms17-010',
            output: 'CRITICAL: Host is VULNERABLE to MS17-010 (EternalBlue) Remote Code Execution! Stage payload injected.',
          },
        ],
      },
      {
        portid: 8443,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'https-alt', product: 'Cobalt Strike C2 Malleable Listener' },
        scripts: [
          {
            id: 'jarm-fingerprint',
            output: 'JARM: 07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1 (Cobalt Strike Profile Match)',
          },
        ],
      },
    ],
    generateScripts: () => [
      {
        id: 'lateral-movement-audit',
        output: 'High-volume outbound SMB scans initiated from this host toward adjacent /24 subnet addresses.',
      },
    ],
  },
  {
    threatType: 'arp_spoofer',
    name: 'Rogue AP & MITM Gateway (Credential Harvester)',
    severity: 'HIGH',
    hostname: 'guest-portal-backup.lan',
    vendor: 'Alfa Network Inc.',
    macPrefix: '00:C0:CA',
    osFamily: 'Linux',
    osName: 'OpenWrt / Evil AP (Linux 5.15)',
    deviceType: 'router',
    description: 'A rogue wireless access point executing ARP cache poisoning against the local gateway, capturing cleartext passwords through a fake captive portal.',
    detectionClues: [
      'Port 3128 open running Squid MITM SSL proxy',
      'Port 80 serves a spoofed captive portal login harvesting corporate credentials',
      'Alfa Network high-power Wi-Fi adapter MAC address on an enterprise wired network',
    ],
    remediation: 'Enable Dynamic ARP Inspection (DAI) and 802.1X Port Security on the network switches; trace MAC address to the physical wall jack.',
    generatePorts: () => [
      {
        portid: 80,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'http', product: 'EvilPortal Credential Harvester v2' },
        scripts: [
          {
            id: 'http-title',
            output: 'Title: Corporate Wi-Fi Authentication Portal (Phishing Warning: Self-Signed Cert)',
          },
        ],
      },
      {
        portid: 3128,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'squid-http', product: 'Squid Transparent Interception Proxy', version: '5.7' },
      },
    ],
    generateScripts: () => [
      {
        id: 'arp-spoof-detector',
        output: 'WARNING: Host is emitting duplicate gratuitous ARP announcements claiming the Gateway IP address (192.168.1.1).',
      },
    ],
  },
  {
    threatType: 'backdoor_shell',
    name: 'Backdoored Legacy Server (vsftpd 2.3.4 Backdoor)',
    severity: 'HIGH',
    hostname: 'archive-files-legacy.lan',
    vendor: 'Supermicro',
    macPrefix: '00:30:48',
    osFamily: 'Linux',
    osName: 'Debian 6.0 Squeeze (Outdated)',
    deviceType: 'server',
    cve: 'CVE-2011-2523',
    description: 'An unmaintained legacy storage server running the historic vsftpd 2.3.4 smiling face backdoor, exposing a root shell on port 6200.',
    detectionClues: [
      'Port 21 running compromised vsftpd 2.3.4 banner',
      'Port 6200 open with an unauthenticated root command shell',
      'Outdated Debian Squeeze operating system',
    ],
    remediation: 'Decommission legacy server immediately, sanitize backups, or upgrade vsftpd to a modern supported release.',
    generatePorts: () => [
      {
        portid: 21,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'ftp', product: 'vsftpd', version: '2.3.4 (Backdoored)' },
        scripts: [
          {
            id: 'ftp-vsftpd-backdoor',
            output: 'VULNERABLE: vsftpd 2.3.4 backdoor execution confirmed. Root shell spawned on port 6200.',
          },
        ],
      },
      {
        portid: 6200,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'unknown', product: 'Root Interactive Shell (vsftpd Backdoor)' },
      },
    ],
    generateScripts: () => [
      {
        id: 'vulners',
        output: 'CVE-2011-2523 - Remote Root Shell Execution in vsftpd 2.3.4 (CVSS 9.8)',
      },
    ],
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// Scenario Generator Implementation
// ─────────────────────────────────────────────────────────────────────────────

export function generateNetworkScenario(options: ScenarioGeneratorOptions = {}): {
  scan: NmapRun;
  threats: MaliciousThreatInfo[];
} {
  const subnetBase = options.subnet ? options.subnet.split('/')[0].replace(/\.\d+$/, '') : '192.168.1';
  const gatewayIp = options.gatewayIp || `${subnetBase}.1`;
  const totalCount = options.totalHosts || 22;
  const threatCount = Math.min(options.threatCount !== undefined ? options.threatCount : 2, 5);

  const usedHostOctets = new Set<number>([1]); // 1 reserved for gateway
  const getUniqueOctet = (): number => {
    let octet: number;
    do {
      octet = randomInt(2, 254);
    } while (usedHostOctets.has(octet));
    usedHostOctets.add(octet);
    return octet;
  };

  const hosts: NmapHost[] = [];
  const threats: MaliciousThreatInfo[] = [];

  // 1. Always create the Gateway Router (.1)
  const gatewayHost: NmapHost = {
    id: gatewayIp,
    ipv4: gatewayIp,
    status: { state: 'up', reason: 'arp-response', reason_ttl: 0 },
    primaryHostname: 'gateway-router.local',
    hostnames: [{ name: 'gateway-router.local', type: 'PTR' }],
    addresses: [
      { addr: gatewayIp, addrtype: 'ipv4', vendor: 'Ubiquiti Networks' },
      { addr: 'F0:9F:C2:11:22:33', addrtype: 'mac', vendor: 'Ubiquiti UniFi Dream Machine Pro' },
    ],
    ports: [
      {
        portid: 53,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'domain', product: 'dnsmasq / Unbound DNS Cache', version: '2.89' },
      },
      {
        portid: 80,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'http', product: 'UniFi Network Gateway Web Console' },
      },
      {
        portid: 443,
        protocol: 'tcp',
        state: 'open',
        service: { name: 'https', product: 'UniFi OS SSL Management Portal' },
      },
    ],
    primaryOs: 'UniFi OS Linux 4.19',
    osFamily: 'Linux',
    deviceType: 'router',
    distance: 1,
    latencyMs: 0.35,
    trace: {
      hops: [{ ttl: 1, ipaddr: gatewayIp, rtt: 0.35, host: 'gateway-router.local' }],
    },
    tags: ['infrastructure', 'gateway'],
    comments: 'Default Network Gateway and DNS resolver.',
    customData: { isGateway: true, isMalicious: false },
  };
  hosts.push(gatewayHost);

  // 2. Select Malicious Threats
  const shuffledBlueprints = [...MALICIOUS_THREAT_BLUEPRINTS].sort(() => 0.5 - Math.random());
  const selectedBlueprints = shuffledBlueprints.slice(0, threatCount);

  for (const bp of selectedBlueprints) {
    const octet = getUniqueOctet();
    const ip = `${subnetBase}.${octet}`;
    const mac = generateMac(bp.macPrefix);
    const ports = bp.generatePorts();
    const scripts = bp.generateScripts();

    const threatInfo: MaliciousThreatInfo = {
      threatId: `threat-${octet}`,
      threatType: bp.threatType,
      name: bp.name,
      severity: bp.severity,
      description: bp.description,
      detectionClues: bp.detectionClues,
      remediation: bp.remediation,
      cve: bp.cve,
      isNeutralized: false,
    };
    threats.push(threatInfo);

    const maliciousHost: NmapHost = {
      id: ip,
      ipv4: ip,
      status: {
        state: 'up',
        reason: randomElement(['syn-ack', 'echo-reply', 'arp-response']),
      },
      primaryHostname: bp.hostname,
      hostnames: [{ name: bp.hostname, type: 'PTR' }],
      addresses: [
        { addr: ip, addrtype: 'ipv4', vendor: bp.vendor },
        { addr: mac, addrtype: 'mac', vendor: bp.vendor },
      ],
      ports,
      hostscripts: scripts,
      primaryOs: bp.osName,
      osFamily: bp.osFamily,
      deviceType: bp.deviceType,
      distance: 1,
      latencyMs: bp.threatType === 'cryptominer' ? randomInt(55, 95) : Number((Math.random() * 6 + 1.2).toFixed(2)),
      trace: {
        hops: [
          { ttl: 1, ipaddr: gatewayIp, rtt: 0.35, host: 'gateway-router.local' },
          { ttl: 2, ipaddr: ip, rtt: 1.8, host: bp.hostname },
        ],
      },
      tags: ['simulated', 'target'],
      customData: {
        isMalicious: true,
        threatInfo,
      },
    };
    hosts.push(maliciousHost);
  }

  // 3. Fill remaining count with Normal Organic Devices
  const normalArchetypesPool: DeviceArchetype[] = [];
  if (options.includeSmartphones !== false) normalArchetypesPool.push(...PHONE_ARCHETYPES);
  if (options.includeLaptops !== false) normalArchetypesPool.push(...LAPTOP_ARCHETYPES);
  if (options.includeIoT !== false) normalArchetypesPool.push(...IOT_ARCHETYPES);

  const remainingCount = totalCount - hosts.length;

  for (let i = 0; i < remainingCount; i++) {
    const archetype = randomElement(normalArchetypesPool);
    const octet = getUniqueOctet();
    const ip = `${subnetBase}.${octet}`;
    const mac = generateMac(archetype.macPrefix);
    const hostname = `${randomElement(archetype.names).replace(/\s+/g, '-')}`;
    const ports = archetype.ports();

    const normalHost: NmapHost = {
      id: ip,
      ipv4: ip,
      status: {
        state: 'up',
        reason: randomElement(['arp-response', 'syn-ack', 'echo-reply']),
      },
      primaryHostname: hostname,
      hostnames: [{ name: hostname, type: 'PTR' }],
      addresses: [
        { addr: ip, addrtype: 'ipv4', vendor: archetype.vendor },
        { addr: mac, addrtype: 'mac', vendor: archetype.vendor },
      ],
      ports,
      primaryOs: archetype.osName,
      osFamily: archetype.osFamily,
      deviceType: archetype.deviceType,
      distance: 1,
      latencyMs: Number((Math.random() * 5 + 0.8).toFixed(2)),
      trace: {
        hops: [
          { ttl: 1, ipaddr: gatewayIp, rtt: 0.35, host: 'gateway-router.local' },
          { ttl: 2, ipaddr: ip, rtt: 1.5, host: hostname },
        ],
      },
      tags: [archetype.category],
      comments: `Normal authorized network device (${archetype.vendor}).`,
      customData: {
        isMalicious: false,
        deviceCategory: archetype.category,
      },
    };
    hosts.push(normalHost);
  }

  // Sort hosts by IP octet for realistic subnet order
  hosts.sort((a, b) => {
    const octA = parseInt(a.ipv4?.split('.')[3] || '0', 10);
    const octB = parseInt(b.ipv4?.split('.')[3] || '0', 10);
    return octA - octB;
  });

  const runstats = {
    finished: {
      time: Math.floor(Date.now() / 1000),
      timestr: new Date().toUTCString(),
      summary: `Nmap scan completed in 2.45s: ${hosts.length} IP addresses (${hosts.length} hosts up)`,
      elapsed: 2.45,
    },
    hosts: {
      up: hosts.length,
      down: 0,
      total: hosts.length,
    },
  };

  const scan: NmapRun = {
    scanner: 'nmap',
    args: `nmap -sS -sV -O -A --traceroute -T4 ${subnetBase}.0/24`,
    start: Math.floor(Date.now() / 1000) - 3,
    startstr: new Date().toUTCString(),
    version: '7.94',
    xmloutputversion: '1.05',
    hosts,
    runstats,
  };

  return { scan, threats };
}
