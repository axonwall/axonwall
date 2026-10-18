import { getSession } from './auth';
import fs from 'fs';
import path from 'path';
import { spawn } from 'child_process';
import os from 'os';

export interface CapturedPacket {
  index: number;
  timestamp: string;
  srcIp: string;
  srcPort: string;
  dstIp: string;
  dstPort: string;
  protocol: string;
  length: number;
  info: string;
}

export interface CaptureResult {
  id: string;
  interface: string;
  filter: string;
  packetCount: number;
  packets: CapturedPacket[];
  pcapPath: string;
  startedAt: string;
  completedAt: string;
}

// In-memory cache for recent capture summaries
const recentCaptures = new Map<string, CaptureResult>();

function getCaptureDir(): string {
  const prodDir = '/var/log/axonwall/captures';
  try {
    if (!fs.existsSync(prodDir)) {
      fs.mkdirSync(prodDir, { recursive: true });
    }
    return prodDir;
  } catch {
    const tmpDir = path.join(os.tmpdir(), 'axonwall-captures');
    if (!fs.existsSync(tmpDir)) {
      fs.mkdirSync(tmpDir, { recursive: true });
    }
    return tmpDir;
  }
}

/**
 * Builds a valid binary PCAP (libpcap format) file from captured packet records
 * so users can open downloaded files in Wireshark or tcpdump without errors.
 */
export function buildPcapBinary(packets: CapturedPacket[]): Buffer {
  const chunks: Buffer[] = [];

  // Global Libpcap Header (24 bytes)
  // Magic: 0xa1b2c3d4 (little-endian: d4 c3 b2 a1)
  const globalHeader = Buffer.alloc(24);
  globalHeader.writeUInt32LE(0xa1b2c3d4, 0); // Magic number
  globalHeader.writeUInt16LE(2, 4);          // Major version
  globalHeader.writeUInt16LE(4, 6);          // Minor version
  globalHeader.writeInt32LE(0, 8);           // Timezone GMT
  globalHeader.writeUInt32LE(0, 12);         // Sigfigs
  globalHeader.writeUInt32LE(65535, 16);     // Snaplen
  globalHeader.writeUInt32LE(1, 20);         // Linktype: Ethernet (1)
  chunks.push(globalHeader);

  const nowSec = Math.floor(Date.now() / 1000);

  for (let i = 0; i < packets.length; i++) {
    const pkt = packets[i];
    // Construct synthetic Ethernet (14B) + IPv4 (20B) + UDP/TCP frame
    const payload = Buffer.from(pkt.info || 'Axonwall live capture packet data');
    const ethHeader = Buffer.alloc(14);
    // Dest MAC: 02:00:00:00:00:02, Src MAC: 02:00:00:00:00:01
    ethHeader[0] = 0x02; ethHeader[5] = 0x02;
    ethHeader[6] = 0x02; ethHeader[11] = 0x01;
    ethHeader.writeUInt16BE(0x0800, 12); // EtherType IPv4

    const ipHeader = Buffer.alloc(20);
    ipHeader[0] = 0x45; // IPv4, Header Length 5 (20 bytes)
    ipHeader[1] = 0x00; // DSCP
    const totalLen = 20 + 8 + payload.length;
    ipHeader.writeUInt16BE(totalLen, 2);
    ipHeader.writeUInt16BE(1000 + i, 4); // ID
    ipHeader.writeUInt16BE(0x4000, 6);   // Don't fragment
    ipHeader[8] = 64;                    // TTL

    const isTcp = pkt.protocol.includes('TCP') || pkt.protocol.includes('TLS') || pkt.protocol.includes('HTTP');
    ipHeader[9] = isTcp ? 6 : 17;        // Protocol: TCP (6) or UDP (17)

    // Parse src and dst IP
    const parseIPv4 = (ipStr: string, offset: number) => {
      const parts = ipStr.split('.').map(n => parseInt(n, 10) || 0);
      for (let p = 0; p < 4; p++) {
        ipHeader[offset + p] = parts[p] || 0;
      }
    };
    parseIPv4(pkt.srcIp || '192.168.1.100', 12);
    parseIPv4(pkt.dstIp || '1.1.1.1', 16);

    // Simple transport layer (8 bytes)
    const transportHeader = Buffer.alloc(8);
    const srcPort = parseInt(pkt.srcPort, 10) || 12345;
    const dstPort = parseInt(pkt.dstPort, 10) || 80;
    transportHeader.writeUInt16BE(srcPort, 0);
    transportHeader.writeUInt16BE(dstPort, 2);
    transportHeader.writeUInt16BE(8 + payload.length, 4);
    transportHeader.writeUInt16BE(0x0000, 6);

    const frame = Buffer.concat([ethHeader, ipHeader, transportHeader, payload]);

    // Packet Header (16 bytes)
    const pktHeader = Buffer.alloc(16);
    pktHeader.writeUInt32LE(nowSec, 0);                 // Timestamp seconds
    pktHeader.writeUInt32LE((i * 15000) % 1000000, 4);   // Timestamp microseconds
    pktHeader.writeUInt32LE(frame.length, 8);           // Captured packet length
    pktHeader.writeUInt32LE(frame.length, 12);          // Original wire packet length

    chunks.push(pktHeader);
    chunks.push(frame);
  }

  return Buffer.concat(chunks);
}

export async function runLivePacketCapture({
  iface = 'any',
  filter = '',
  count = 50,
}: {
  iface?: string;
  filter?: string;
  count?: number;
}): Promise<CaptureResult> {
  const session = await getSession();
  if (!session || !session.roles.includes('admin')) {
    throw new Error('Unauthorized: Admin credentials required');
  }
  if (session.passwordChangeRequired) {
    throw new Error('Password change required before performing this action');
  }

  // Sanitize interface
  const trimmedIface = (iface || 'any').trim();
  if (
    trimmedIface.startsWith('-') ||
    trimmedIface.includes('..') ||
    trimmedIface.includes('/') ||
    !/^[a-zA-Z0-9_.:-]+$/.test(trimmedIface)
  ) {
    throw new Error('Invalid interface name');
  }
  const cleanIface = trimmedIface;
  
  // Sanitize filter and reject options starting with '-'
  const cleanFilter = (filter || '').trim();
  const filterTokens: string[] = [];
  if (cleanFilter) {
    const rawTokens = cleanFilter.split(/\s+/);
    for (const tok of rawTokens) {
      if (tok.startsWith('-')) {
        throw new Error(`Invalid filter token starting with '-': ${tok}`);
      }
      if (!/^[a-zA-Z0-9_.:/()=!<>&|[\]-]+$/.test(tok)) {
        throw new Error(`Invalid characters in BPF filter token: ${tok}`);
      }
      filterTokens.push(tok);
    }
  }

  const boundedCount = Math.max(1, Math.min(200, count));
  const captureId = `pcap-${Date.now()}-${cleanIface.replace(/[^a-zA-Z0-9_-]/g, '_')}`;
  const captureDir = getCaptureDir();
  const pcapFilePath = path.join(captureDir, `${captureId}.pcap`);
  const startedAt = new Date().toISOString();

  let packets: CapturedPacket[] = [];

  try {
    // Attempt live execution using tcpdump
    packets = await executeTcpdump(cleanIface, filterTokens, boundedCount, pcapFilePath);
  } catch {
    // Return empty list if tcpdump fails or interface is uncapturable
    packets = [];
    const binary = buildPcapBinary([]);
    fs.writeFileSync(pcapFilePath, binary);
  }

  const completedAt = new Date().toISOString();
  const result: CaptureResult = {
    id: captureId,
    interface: cleanIface,
    filter: cleanFilter,
    packetCount: packets.length,
    packets,
    pcapPath: pcapFilePath,
    startedAt,
    completedAt,
  };

  recentCaptures.set(captureId, result);
  return result;
}

function executeTcpdump(
  iface: string,
  filterTokens: string[],
  count: number,
  outputPath: string
): Promise<CapturedPacket[]> {
  return new Promise((resolve, reject) => {
    const args = ['-i', iface, '-c', String(count), '-nn', '-s', '0', '-w', outputPath];
    if (filterTokens.length > 0) {
      args.push('--', ...filterTokens);
    }

    const proc = spawn('tcpdump', args, { timeout: 15000 });

    proc.on('error', (err) => {
      reject(err);
    });

    proc.on('close', (code) => {
      if (!fs.existsSync(outputPath) || fs.statSync(outputPath).size === 0) {
        return reject(new Error(`tcpdump exited with code ${code} without output`));
      }

      // Read back with tcpdump -nn -tt -r
      const readProc = spawn('tcpdump', ['-nn', '-tt', '-r', outputPath]);
      let stdout = '';

      readProc.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      readProc.on('close', () => {
        const parsed = parseTcpdumpText(stdout);
        resolve(parsed);
      });

      readProc.on('error', reject);
    });
  });
}

function parseTcpdumpText(raw: string): CapturedPacket[] {
  const lines = raw.split('\n');
  const packets: CapturedPacket[] = [];
  const ipPortRegex = /^(\d+\.\d+)\s+IP\s+([0-9a-fA-F.:]+)\.([0-9]+)\s+>\s+([0-9a-fA-F.:]+)\.([0-9]+):\s+(.*)$/;
  const genericIpRegex = /^(\d+\.\d+)\s+IP\s+([0-9a-fA-F.:]+)\s+>\s+([0-9a-fA-F.:]+):\s+(.*)$/;

  let idx = 1;
  for (const line of lines) {
    if (!line.trim()) continue;

    const matchPort = line.match(ipPortRegex);
    if (matchPort) {
      const tsSec = parseFloat(matchPort[1]);
      const date = new Date(tsSec * 1000);
      const timeStr = date.toTimeString().split(' ')[0] + '.' + String(Math.floor((tsSec % 1) * 1000000)).padStart(6, '0');
      const srcPort = matchPort[3];
      const dstPort = matchPort[5];
      let proto = 'TCP';
      if (srcPort === '53' || dstPort === '53') proto = 'DNS';
      else if (srcPort === '443' || dstPort === '443') proto = 'TLS/HTTPS';
      else if (srcPort === '80' || dstPort === '80') proto = 'HTTP';
      else if (srcPort === '22' || dstPort === '22') proto = 'SSH';
      else if (srcPort === '51820' || dstPort === '51820') proto = 'WireGuard';
      else if (!line.includes('Flags')) proto = 'UDP';

      packets.push({
        index: idx++,
        timestamp: timeStr,
        srcIp: matchPort[2],
        srcPort,
        dstIp: matchPort[4],
        dstPort,
        protocol: proto,
        length: line.length,
        info: matchPort[6],
      });
      continue;
    }

    const matchGeneric = line.match(genericIpRegex);
    if (matchGeneric) {
      const tsSec = parseFloat(matchGeneric[1]);
      const date = new Date(tsSec * 1000);
      const timeStr = date.toTimeString().split(' ')[0] + '.' + String(Math.floor((tsSec % 1) * 1000000)).padStart(6, '0');
      const info = matchGeneric[4];
      const proto = info.includes('ICMP') ? 'ICMP' : 'IP';

      packets.push({
        index: idx++,
        timestamp: timeStr,
        srcIp: matchGeneric[2],
        srcPort: '-',
        dstIp: matchGeneric[3],
        dstPort: '-',
        protocol: proto,
        length: line.length,
        info,
      });
    }
  }

  return packets;
}

export function getCaptureFile(id: string): { filePath: string; exists: boolean } {
  if (!id || id.includes('..') || id.includes('/') || id.includes('\\')) {
    return { filePath: '', exists: false };
  }
  const sanitizedId = (id || '').replace(/[^a-zA-Z0-9_.-]/g, '');
  if (!sanitizedId || sanitizedId !== id) {
    return { filePath: '', exists: false };
  }
  const captureDir = getCaptureDir();
  let filePath = path.resolve(captureDir, `${sanitizedId}.pcap`);
  if (!filePath.startsWith(path.resolve(captureDir))) {
    return { filePath: '', exists: false };
  }
  if (!fs.existsSync(filePath)) {
    const altPath = path.resolve(captureDir, `${sanitizedId.replace(/\./g, '_')}.pcap`);
    if (altPath.startsWith(path.resolve(captureDir)) && fs.existsSync(altPath)) {
      filePath = altPath;
    }
  }
  return {
    filePath,
    exists: fs.existsSync(filePath),
  };
}
