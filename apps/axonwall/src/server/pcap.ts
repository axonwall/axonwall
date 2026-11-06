import { getSession } from './auth';
import { callAgentApi } from './agent-client';
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
  for (const prodDir of ['/var/lib/axonwall/captures', '/var/log/axonwall/captures']) {
    try {
      if (!fs.existsSync(prodDir)) {
        fs.mkdirSync(prodDir, { recursive: true, mode: 0o775 });
      }
      fs.accessSync(prodDir, fs.constants.W_OK);
      return prodDir;
    } catch {}
  }
  const tmpDir = path.join(os.tmpdir(), 'axonwall-captures');
  if (!fs.existsSync(tmpDir)) {
    fs.mkdirSync(tmpDir, { recursive: true, mode: 0o775 });
  }
  return tmpDir;
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

    const isTcp = pkt.protocol.includes('TCP') || pkt.protocol.includes('TLS') || pkt.protocol.includes('HTTP') || pkt.protocol.includes('SSH');
    const transportLen = isTcp ? 20 : 8;

    const ipHeader = Buffer.alloc(20);
    ipHeader[0] = 0x45; // IPv4, Header Length 5 (20 bytes)
    ipHeader[1] = 0x00; // DSCP
    const totalLen = 20 + transportLen + payload.length;
    ipHeader.writeUInt16BE(totalLen, 2);
    ipHeader.writeUInt16BE((1000 + i) & 0xffff, 4); // ID
    ipHeader.writeUInt16BE(0x4000, 6);   // Don't fragment
    ipHeader[8] = 64;                    // TTL
    ipHeader[9] = isTcp ? 6 : 17;        // Protocol: TCP (6) or UDP (17)

    // Parse src and dst IP
    const parseIPv4 = (ipStr: string, offset: number) => {
      const parts = ipStr.split('.').map(n => parseInt(n, 10) || 0);
      for (let p = 0; p < 4; p++) {
        ipHeader[offset + p] = (parts[p] || 0) & 0xff;
      }
    };
    parseIPv4(pkt.srcIp || '192.168.1.100', 12);
    parseIPv4(pkt.dstIp || '1.1.1.1', 16);

    // Compute IPv4 header checksum
    let csum = 0;
    for (let j = 0; j < 20; j += 2) {
      csum += ipHeader.readUInt16BE(j);
    }
    while (csum > 0xffff) {
      csum = (csum & 0xffff) + (csum >>> 16);
    }
    ipHeader.writeUInt16BE((~csum) & 0xffff, 10);

    // Transport layer (20 bytes for TCP, 8 bytes for UDP)
    const transportHeader = Buffer.alloc(transportLen);
    const srcPort = Math.min(65535, Math.max(0, parseInt(pkt.srcPort, 10) || 12345));
    const dstPort = Math.min(65535, Math.max(0, parseInt(pkt.dstPort, 10) || 80));
    transportHeader.writeUInt16BE(srcPort, 0);
    transportHeader.writeUInt16BE(dstPort, 2);
    if (isTcp) {
      transportHeader.writeUInt32BE(1, 4);   // Seq number
      transportHeader.writeUInt32BE(1, 8);   // Ack number
      transportHeader[12] = 0x50;            // Data offset: 5 (20 bytes)
      transportHeader[13] = 0x18;            // Flags: PSH, ACK
      transportHeader.writeUInt16BE(64240, 14); // Window size
    } else {
      transportHeader.writeUInt16BE(8 + payload.length, 4);
      transportHeader.writeUInt16BE(0x0000, 6);
    }

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

  // Delegate live capture to privileged axonwalld (CAP_NET_RAW) first
  try {
    const daemonResp = await callAgentApi<{ success: boolean; output: string }>('/v1/diagnostic', 'POST', {
      type: 4, // DIAGNOSTIC_TYPE_PACKET_CAPTURE
      interface: cleanIface,
      target: cleanFilter,
      count: boundedCount,
    });
    if (daemonResp?.success && daemonResp.output) {
      const parsed = JSON.parse(daemonResp.output) as CaptureResult;
      if (parsed && parsed.id && Array.isArray(parsed.packets)) {
        recentCaptures.set(parsed.id, parsed);
        return parsed;
      }
    }
  } catch {}

  const captureId = `pcap-${Date.now()}-${cleanIface.replace(/[^a-zA-Z0-9_-]/g, '_')}`;
  const captureDir = getCaptureDir();
  const pcapFilePath = path.join(captureDir, `${captureId}.pcap`);
  const startedAt = new Date().toISOString();

  let packets: CapturedPacket[] = [];

  try {
    // Attempt live execution using tcpdump
    packets = await executeTcpdump(cleanIface, filterTokens, boundedCount, pcapFilePath);
  } catch (err: any) {
    // C20: a failed capture backend must not masquerade as a
    // zero-traffic capture. Throw, so the caller shows an error that
    // distinguishes "ran, saw nothing" (packetCount 0, no throw) from
    // "could not capture". No empty pcap is written or registered.
    throw new Error(
      `Packet capture failed on interface ${cleanIface}: ${err?.message || 'tcpdump failed'} — no packets were captured.`
    );
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
      let stderr = '';

      readProc.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      readProc.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      readProc.on('close', (code) => {
        // N14: a corrupt/truncated pcap makes tcpdump -r fail with
        // empty stdout, which used to parse to [] and resolve as a
        // successful empty capture — the same shape as "ran, saw
        // nothing". A failed read-back is an error, not zero packets.
        if (code !== 0) {
          const detail = stderr.trim().split('\n')[0] || `tcpdump exited with code ${code}`;
          return reject(new Error(`Failed to read back capture file: ${detail}`));
        }
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
  const ip6PortRegex = /^(\d+\.\d+)\s+IP6\s+([0-9a-fA-F:]+)\.([0-9]+)\s+>\s+([0-9a-fA-F:]+)\.([0-9]+):\s+(.*)$/;
  const genericIpRegex = /^(\d+\.\d+)\s+IP\s+([0-9a-fA-F.:]+)\s+>\s+([0-9a-fA-F.:]+):\s+(.*)$/;
  const genericIp6Regex = /^(\d+\.\d+)\s+IP6\s+([0-9a-fA-F:]+)\s+>\s+([0-9a-fA-F:]+):\s+(.*)$/;
  const arpRegex = /^(\d+\.\d+)\s+ARP,\s+(.*)$/;
  // Any other tcpdump line (STP, LLDP, ...): tcpdump prints one line
  // per frame, so count it instead of silently dropping it.
  const genericLineRegex = /^(\d+\.\d+)\s+([A-Za-z0-9]+)[,\s]+(.*)$/;

  const toTimeStr = (tsSec: number): string => {
    const date = new Date(tsSec * 1000);
    return date.toTimeString().split(' ')[0] + '.' + String(Math.floor((tsSec % 1) * 1000000)).padStart(6, '0');
  };
  // N13: tcpdump reports the frame length as `length N` in the packet
  // summary. The old code used line.length — the length of the printed
  // text line — and presented it as frame bytes (~90 B for a 1500 B
  // frame). Parse the real reported length; 0 when tcpdump omits it.
  const frameLength = (info: string): number => {
    const m = info.match(/length (\d+)/);
    return m ? parseInt(m[1], 10) : 0;
  };

  let idx = 1;
  for (const line of lines) {
    if (!line.trim()) continue;

    const matchPort = line.match(ipPortRegex) || line.match(ip6PortRegex);
    if (matchPort) {
      const tsSec = parseFloat(matchPort[1]);
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
        timestamp: toTimeStr(tsSec),
        srcIp: matchPort[2],
        srcPort,
        dstIp: matchPort[4],
        dstPort,
        protocol: proto,
        length: frameLength(matchPort[6]),
        info: matchPort[6],
      });
      continue;
    }

    const matchGeneric = line.match(genericIpRegex) || line.match(genericIp6Regex);
    if (matchGeneric) {
      const tsSec = parseFloat(matchGeneric[1]);
      const info = matchGeneric[4];
      const proto = info.includes('ICMP') ? 'ICMP' : line.includes('IP6') ? 'IP6' : 'IP';

      packets.push({
        index: idx++,
        timestamp: toTimeStr(tsSec),
        srcIp: matchGeneric[2],
        srcPort: '-',
        dstIp: matchGeneric[3],
        dstPort: '-',
        protocol: proto,
        length: frameLength(info),
        info,
      });
      continue;
    }

    // N13: ARP and other non-IP frames used to be silently dropped,
    // so packetCount undercounted the frames in the downloaded .pcap.
    const matchArp = line.match(arpRegex);
    if (matchArp) {
      const tsSec = parseFloat(matchArp[1]);
      const info = matchArp[2];
      let srcIp = '-';
      let dstIp = '-';
      const request = info.match(/who-has\s+([0-9a-fA-F.:]+)\s+tel+l\s+([0-9a-fA-F.:]+)/);
      const reply = info.match(/([0-9a-fA-F.:]+)\s+is-at\s+/);
      if (request) {
        dstIp = request[1];
        srcIp = request[2];
      } else if (reply) {
        srcIp = reply[1];
      }
      packets.push({
        index: idx++,
        timestamp: toTimeStr(tsSec),
        srcIp,
        srcPort: '-',
        dstIp,
        dstPort: '-',
        protocol: 'ARP',
        length: frameLength(info),
        info: `ARP, ${info}`,
      });
      continue;
    }

    const matchOther = line.match(genericLineRegex);
    if (matchOther) {
      packets.push({
        index: idx++,
        timestamp: toTimeStr(parseFloat(matchOther[1])),
        srcIp: '-',
        srcPort: '-',
        dstIp: '-',
        dstPort: '-',
        protocol: matchOther[2].toUpperCase(),
        length: frameLength(matchOther[3]),
        info: matchOther[3],
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
  const candidateDirs = [
    getCaptureDir(),
    '/var/lib/axonwall/captures',
    '/var/log/axonwall/captures',
    path.join(os.tmpdir(), 'axonwall-captures'),
  ];
  for (const dir of candidateDirs) {
    const resolvedDir = path.resolve(dir);
    for (const candidateName of [`${sanitizedId}.pcap`, `${sanitizedId.replace(/\./g, '_')}.pcap`]) {
      const candidatePath = path.resolve(resolvedDir, candidateName);
      if (candidatePath.startsWith(resolvedDir) && fs.existsSync(candidatePath)) {
        return { filePath: candidatePath, exists: true };
      }
    }
  }
  const captureDir = getCaptureDir();
  const filePath = path.resolve(captureDir, `${sanitizedId}.pcap`);
  return {
    filePath,
    exists: false,
  };
}
