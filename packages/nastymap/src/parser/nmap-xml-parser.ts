import { XMLParser } from 'fast-xml-parser';
import type {
  NmapAddress,
  NmapHost,
  NmapHostname,
  NmapHop,
  NmapOs,
  NmapOsClass,
  NmapOsMatch,
  NmapPort,
  NmapRun,
  NmapRunStats,
  NmapScanInfo,
  NmapScript,
  NmapService,
  NmapTimes,
  NmapTrace,
  NmapUptime,
} from '../types/nmap';
import { geocodeIp } from '../geoip/geocoder';

export const MAX_NMAP_XML_BYTES = 25 * 1024 * 1024;
export const MAX_NMAP_XML_DEPTH = 128;

const FORBIDDEN_ELEMENT_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function getUtf8ByteLength(input: string): number {
  const maybeBuffer = (globalThis as { Buffer?: { byteLength?: (s: string, encoding: string) => number } }).Buffer;
  if (maybeBuffer && typeof maybeBuffer.byteLength === 'function') {
    return maybeBuffer.byteLength(input, 'utf8');
  }
  let bytes = 0;
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    if (code <= 0x7f) {
      bytes += 1;
    } else if (code <= 0x7ff) {
      bytes += 2;
    } else if (code >= 0xd800 && code <= 0xdbff) {
      if (i + 1 < input.length) {
        const next = input.charCodeAt(i + 1);
        if (next >= 0xdc00 && next <= 0xdfff) {
          bytes += 4;
          i += 1;
          continue;
        }
      }
      bytes += 3;
    } else {
      bytes += 3;
    }
  }
  return bytes;
}

function assertSafeXmlNesting(xml: string, maxDepth: number = MAX_NMAP_XML_DEPTH): string | null {
  let depth = 0;
  const len = xml.length;
  let i = 0;

  while (i < len) {
    const lt = xml.indexOf('<', i);
    if (lt === -1) break;

    if (xml.startsWith('<!--', lt)) {
      const end = xml.indexOf('-->', lt + 4);
      if (end === -1) return 'Unterminated XML comment.';
      i = end + 3;
      continue;
    }

    if (xml.startsWith('<![CDATA[', lt)) {
      const end = xml.indexOf(']]>', lt + 9);
      if (end === -1) return 'Unterminated XML CDATA section.';
      i = end + 3;
      continue;
    }

    if (xml.startsWith('<?', lt)) {
      const end = xml.indexOf('?>', lt + 2);
      if (end === -1) return 'Unterminated XML processing instruction.';
      i = end + 2;
      continue;
    }

    if (xml.startsWith('<!', lt)) {
      let j = lt + 2;
      let quote = 0;
      let bracketDepth = 0;
      while (j < len) {
        const ch = xml.charCodeAt(j);
        if (quote !== 0) {
          if (ch === quote) quote = 0;
        } else if (ch === 34 || ch === 39) {
          quote = ch;
        } else if (ch === 91) {
          bracketDepth++;
        } else if (ch === 93 && bracketDepth > 0) {
          bracketDepth--;
        } else if (ch === 62 && bracketDepth === 0) {
          break;
        }
        j++;
      }
      if (j >= len) return 'Unterminated XML declaration.';
      const decl = xml.slice(lt, j + 1);
      if (/<!ENTITY\b/i.test(decl)) {
        return 'XML entity declarations are not permitted.';
      }
      i = j + 1;
      continue;
    }

    const isClosing = xml.charCodeAt(lt + 1) === 47;
    let j = lt + 1;
    let quote = 0;
    let lastNonSpace = 0;
    while (j < len) {
      const ch = xml.charCodeAt(j);
      if (quote !== 0) {
        if (ch === quote) quote = 0;
      } else if (ch === 34 || ch === 39) {
        quote = ch;
        lastNonSpace = ch;
      } else if (ch === 62) {
        break;
      } else if (ch > 32) {
        lastNonSpace = ch;
      }
      j++;
    }
    if (j >= len) break;

    if (isClosing) {
      if (depth > 0) depth--;
    } else if (lastNonSpace !== 47) {
      const firstChar = xml.charCodeAt(lt + 1);
      if (
        (firstChar >= 65 && firstChar <= 90) ||
        (firstChar >= 97 && firstChar <= 122) ||
        firstChar === 95 ||
        firstChar === 58
      ) {
        depth++;
        if (depth > maxDepth) {
          return `XML nesting depth exceeds maximum allowed limit (${maxDepth}).`;
        }
      }
    }

    i = j + 1;
  }

  return null;
}

function validateXmlPayloadSafety(xmlString: string): string | null {
  if (
    xmlString.length > MAX_NMAP_XML_BYTES ||
    (xmlString.length * 3 > MAX_NMAP_XML_BYTES && getUtf8ByteLength(xmlString) > MAX_NMAP_XML_BYTES)
  ) {
    return `Nmap XML payload exceeds maximum allowed size of ${MAX_NMAP_XML_BYTES} bytes (25 MB).`;
  }
  return assertSafeXmlNesting(xmlString, MAX_NMAP_XML_DEPTH);
}

const arrayTags = new Set([
  'host',
  'address',
  'hostname',
  'port',
  'osmatch',
  'osclass',
  'hop',
  'script',
  'scaninfo',
  'cpe',
  'portused',
]);

const xmlParserOptions = {
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  allowBooleanAttributes: true,
  parseNodeValue: false,
  parseAttributeValue: false,
  trimValues: true,
  processEntities: false,
  isArray: (tagName: string) => arrayTags.has(tagName.toLowerCase()),
};

function ensureArray<T>(val: T | T[] | undefined | null): T[] {
  if (!val) return [];
  return Array.isArray(val) ? val : [val];
}

function parseScriptElement(rawScript: any): NmapScript | null {
  if (!rawScript) return null;
  const id = rawScript['@_id'] || 'unknown-script';
  const output = rawScript['@_output'] || (typeof rawScript === 'string' ? rawScript : '');
  const elements: Record<string, string> = {};

  if (rawScript.elem) {
    const rawElems = ensureArray(rawScript.elem);
    for (const elem of rawElems) {
      const key = String(elem['@_key'] || 'val');
      if (FORBIDDEN_ELEMENT_KEYS.has(key)) continue;
      elements[key] = String(elem['#text'] || elem || '');
    }
  }

  return { id, output, elements: Object.keys(elements).length > 0 ? elements : undefined };
}

function parseServiceElement(rawService: any): NmapService | undefined {
  if (!rawService) return undefined;

  const cpeList: string[] = [];
  if (rawService.cpe) {
    const cpes = ensureArray(rawService.cpe);
    for (const cpe of cpes) {
      if (typeof cpe === 'string') cpeList.push(cpe);
      else if (cpe['#text']) cpeList.push(cpe['#text']);
    }
  }

  return {
    name: rawService['@_name'] || 'unknown',
    product: rawService['@_product'],
    version: rawService['@_version'] ? String(rawService['@_version']) : undefined,
    extrainfo: rawService['@_extrainfo'],
    method: rawService['@_method'],
    conf: rawService['@_conf'] ? String(rawService['@_conf']) : undefined,
    cpe: cpeList.length > 0 ? cpeList : undefined,
    tunnel: rawService['@_tunnel'],
    proto: rawService['@_proto'],
    rpcnum: rawService['@_rpcnum'] ? String(rawService['@_rpcnum']) : undefined,
    ostype: rawService['@_ostype'],
    devicetype: rawService['@_devicetype'],
    servicefp: rawService['@_servicefp'],
  };
}

function parsePortElement(rawPort: any): NmapPort {
  const portid = Number(rawPort['@_portid']) || 0;
  const protocol = (rawPort['@_protocol'] || 'tcp').toLowerCase() as NmapPort['protocol'];
  
  const stateObj = rawPort.state || {};
  const state = (stateObj['@_state'] || 'unknown') as NmapPort['state'];
  const reason = stateObj['@_reason'];
  const reason_ttl = stateObj['@_reason_ttl'] ? Number(stateObj['@_reason_ttl']) : undefined;

  const service = parseServiceElement(rawPort.service);

  const scripts: NmapScript[] = [];
  if (rawPort.script) {
    const rawScripts = ensureArray(rawPort.script);
    for (const s of rawScripts) {
      const parsed = parseScriptElement(s);
      if (parsed) scripts.push(parsed);
    }
  }

  return {
    portid,
    protocol,
    state,
    reason,
    reason_ttl,
    service,
    scripts: scripts.length > 0 ? scripts : undefined,
  };
}

function parseOsElement(rawOs: any): NmapOs | undefined {
  if (!rawOs) return undefined;

  const portusedList: Array<{ state: string; proto: string; portid: number }> = [];
  if (rawOs.portused) {
    const rawPortUsed = ensureArray(rawOs.portused);
    for (const pu of rawPortUsed) {
      portusedList.push({
        state: pu['@_state'] || '',
        proto: pu['@_proto'] || 'tcp',
        portid: Number(pu['@_portid']) || 0,
      });
    }
  }

  const osmatches: NmapOsMatch[] = [];
  if (rawOs.osmatch) {
    const rawMatches = ensureArray(rawOs.osmatch);
    for (const m of rawMatches) {
      const name = m['@_name'] || 'Unknown OS';
      const accuracy = Number(m['@_accuracy']) || 0;
      const line = m['@_line'] ? String(m['@_line']) : undefined;

      const osclasses: NmapOsClass[] = [];
      if (m.osclass) {
        const rawClasses = ensureArray(m.osclass);
        for (const oc of rawClasses) {
          const cpes: string[] = [];
          if (oc.cpe) {
            const rawCpes = ensureArray(oc.cpe);
            for (const c of rawCpes) {
              if (typeof c === 'string') cpes.push(c);
              else if (c['#text']) cpes.push(c['#text']);
            }
          }
          osclasses.push({
            type: oc['@_type'],
            vendor: oc['@_vendor'],
            osfamily: oc['@_osfamily'],
            osgen: oc['@_osgen'] ? String(oc['@_osgen']) : undefined,
            accuracy: oc['@_accuracy'] ? Number(oc['@_accuracy']) : undefined,
            cpe: cpes.length > 0 ? cpes : undefined,
          });
        }
      }

      osmatches.push({ name, accuracy, line, osclasses });
    }
  }

  return {
    portused: portusedList.length > 0 ? portusedList : undefined,
    osmatches,
    osfingerprint: rawOs.osfingerprint ? rawOs.osfingerprint['@_fingerprint'] : undefined,
  };
}

function parseTraceElement(rawTrace: any): NmapTrace | undefined {
  if (!rawTrace) return undefined;

  const port = rawTrace['@_port'] ? Number(rawTrace['@_port']) : undefined;
  const proto = rawTrace['@_proto'];
  const hops: NmapHop[] = [];

  if (rawTrace.hop) {
    const rawHops = ensureArray(rawTrace.hop);
    for (const h of rawHops) {
      hops.push({
        ttl: Number(h['@_ttl']) || 1,
        ipaddr: h['@_ipaddr'] || '',
        rtt: h['@_rtt'] !== undefined && h['@_rtt'] !== '--' ? Number(h['@_rtt']) : undefined,
        host: h['@_host'] || undefined,
      });
    }
  }

  // Sort hops by TTL ascending
  hops.sort((a, b) => a.ttl - b.ttl);

  return { port, proto, hops };
}

function parseHostElement(rawHost: any, index: number): NmapHost {
  // Status
  const statusObj = rawHost.status || {};
  const statusState = (statusObj['@_state'] || 'unknown') as NmapHost['status']['state'];
  const statusReason = statusObj['@_reason'];
  const statusReasonTtl = statusObj['@_reason_ttl'] ? Number(statusObj['@_reason_ttl']) : undefined;

  // Addresses
  const addresses: NmapAddress[] = [];
  let ipv4: string | undefined;
  let ipv6: string | undefined;
  let mac: string | undefined;

  if (rawHost.address) {
    const rawAddrs = ensureArray(rawHost.address);
    for (const a of rawAddrs) {
      const addr = a['@_addr'] || '';
      const addrtype = (a['@_addrtype'] || 'ipv4') as NmapAddress['addrtype'];
      const vendor = a['@_vendor'];
      addresses.push({ addr, addrtype, vendor });

      if (addrtype === 'ipv4' && !ipv4) ipv4 = addr;
      if (addrtype === 'ipv6' && !ipv6) ipv6 = addr;
      if (addrtype === 'mac' && !mac) mac = addr;
    }
  }

  // Hostnames
  const hostnames: NmapHostname[] = [];
  if (rawHost.hostnames && rawHost.hostnames.hostname) {
    const rawHn = ensureArray(rawHost.hostnames.hostname);
    for (const hn of rawHn) {
      hostnames.push({
        name: hn['@_name'] || '',
        type: hn['@_type'] || 'user',
      });
    }
  }
  const primaryHostname = hostnames.length > 0 ? hostnames[0].name : undefined;

  // Ports
  const ports: NmapPort[] = [];
  if (rawHost.ports && rawHost.ports.port) {
    const rawPorts = ensureArray(rawHost.ports.port);
    for (const p of rawPorts) {
      ports.push(parsePortElement(p));
    }
  }
  const openPortCount = ports.filter((p) => p.state === 'open').length;

  // OS
  const os = parseOsElement(rawHost.os);
  let primaryOs: string | undefined;
  let osFamily: string | undefined;
  let deviceType: string | undefined;

  if (os && os.osmatches.length > 0) {
    primaryOs = os.osmatches[0].name;
    const firstClass = os.osmatches[0].osclasses[0];
    if (firstClass) {
      osFamily = firstClass.osfamily || (firstClass.vendor ? firstClass.vendor : undefined);
      deviceType = firstClass.type;
    }
  }

  // If no OS class found, attempt to infer from service or hostname
  if (!osFamily) {
    const services = ports.map((p) => (p.service?.name || '') + ' ' + (p.service?.product || '')).join(' ').toLowerCase();
    if (services.includes('windows') || services.includes('microsoft') || services.includes('ms-wbt-server')) {
      osFamily = 'Windows';
    } else if (services.includes('ubuntu') || services.includes('debian') || services.includes('linux') || services.includes('apache')) {
      osFamily = 'Linux';
    } else if (services.includes('cisco') || services.includes('ios')) {
      osFamily = 'Cisco IOS';
      deviceType = 'router';
    } else if (services.includes('freebsd') || services.includes('openbsd')) {
      osFamily = 'BSD';
    } else if (services.includes('apple') || services.includes('darwin')) {
      osFamily = 'macOS';
    } else {
      osFamily = 'Unknown';
    }
  }

  if (!deviceType) {
    const nameLower = (primaryHostname || '').toLowerCase();
    const osLower = (primaryOs || osFamily || '').toLowerCase();
    if (osLower.includes('router') || nameLower.includes('router') || nameLower.includes('gateway') || nameLower.includes('gw')) {
      deviceType = 'router';
    } else if (osLower.includes('switch') || nameLower.includes('switch') || nameLower.includes('sw')) {
      deviceType = 'switch';
    } else if (osLower.includes('firewall') || nameLower.includes('firewall') || nameLower.includes('fw')) {
      deviceType = 'firewall';
    } else if (osLower.includes('printer') || nameLower.includes('printer')) {
      deviceType = 'printer';
    } else if (openPortCount > 0) {
      deviceType = 'server';
    } else {
      deviceType = 'general purpose';
    }
  }

  // Distance / Traceroute
  const distance = rawHost.distance ? Number(rawHost.distance['@_value']) : undefined;
  const trace = parseTraceElement(rawHost.trace);

  // Uptime
  let uptime: NmapUptime | undefined;
  if (rawHost.uptime) {
    uptime = {
      seconds: Number(rawHost.uptime['@_seconds']) || 0,
      lastboot: rawHost.uptime['@_lastboot'],
    };
  }

  // Times
  let times: NmapTimes | undefined;
  let latencyMs: number | undefined;
  if (rawHost.times) {
    const srtt = Number(rawHost.times['@_srtt']) || 0;
    times = {
      srtt,
      rttvar: Number(rawHost.times['@_rttvar']) || 0,
      to: Number(rawHost.times['@_to']) || 0,
    };
    // srtt is in microseconds
    if (srtt > 0) latencyMs = Math.round((srtt / 1000) * 100) / 100;
  }

  // Fallback latency from trace last hop if available
  if (latencyMs === undefined && trace && trace.hops.length > 0) {
    const lastHop = trace.hops[trace.hops.length - 1];
    if (lastHop.rtt !== undefined) latencyMs = lastHop.rtt;
  }

  // Hostscripts
  const hostscripts: NmapScript[] = [];
  if (rawHost.hostscript && rawHost.hostscript.script) {
    const rawScripts = ensureArray(rawHost.hostscript.script);
    for (const s of rawScripts) {
      const parsed = parseScriptElement(s);
      if (parsed) hostscripts.push(parsed);
    }
  }

  const primaryIp = ipv4 || ipv6 || `host-${index + 1}`;
  const geolocation = geocodeIp(primaryIp);

  return {
    id: primaryIp,
    status: {
      state: statusState,
      reason: statusReason,
      reason_ttl: statusReasonTtl,
    },
    addresses,
    hostnames,
    ports,
    os,
    distance,
    trace,
    uptime,
    times,
    hostscripts: hostscripts.length > 0 ? hostscripts : undefined,
    geolocation,
    ipv4,
    ipv6,
    mac,
    primaryHostname,
    primaryOs,
    osFamily,
    deviceType,
    openPortCount,
    latencyMs,
  };
}

/**
 * Parse an Nmap XML string into a structured NmapRun object.
 */
export function parseNmapXml(xmlString: string): NmapRun {
  if (!xmlString || typeof xmlString !== 'string' || !xmlString.trim()) {
    throw new Error('Nmap XML content is empty.');
  }

  const safetyError = validateXmlPayloadSafety(xmlString);
  if (safetyError) {
    throw new Error(safetyError);
  }

  const parser = new XMLParser(xmlParserOptions);
  let parsed: any;
  try {
    parsed = parser.parse(xmlString);
  } catch (err: any) {
    throw new Error(`Failed to parse Nmap XML: ${err.message}`);
  }

  const nmaprun = parsed?.nmaprun;
  if (!nmaprun || typeof nmaprun !== 'object') {
    throw new Error('Invalid Nmap XML: Missing <nmaprun> root tag.');
  }

  const scanner = nmaprun['@_scanner'] || 'nmap';
  const args = nmaprun['@_args'] || '';
  const start = Number(nmaprun['@_start']) || Math.floor(Date.now() / 1000);
  const startstr = nmaprun['@_startstr'] || new Date(start * 1000).toUTCString();
  const version = String(nmaprun['@_version'] || '7.94');
  const xmloutputversion = String(nmaprun['@_xmloutputversion'] || '1.05');

  // Scaninfo
  const scaninfoList: NmapScanInfo[] = [];
  if (nmaprun.scaninfo) {
    const rawScaninfo = ensureArray(nmaprun.scaninfo);
    for (const si of rawScaninfo) {
      scaninfoList.push({
        type: si['@_type'] || 'syn',
        protocol: si['@_protocol'] || 'tcp',
        numservices: Number(si['@_numservices']) || 0,
        services: si['@_services'] || '',
      });
    }
  }

  // Verbose & Debugging
  const verbose = nmaprun.verbose ? { level: Number(nmaprun.verbose['@_level']) || 0 } : undefined;
  const debugging = nmaprun.debugging ? { level: Number(nmaprun.debugging['@_level']) || 0 } : undefined;

  // Hosts
  const hosts: NmapHost[] = [];
  if (nmaprun.host) {
    const rawHosts = ensureArray(nmaprun.host);
    rawHosts.forEach((h, idx) => {
      hosts.push(parseHostElement(h, idx));
    });
  }

  // Runstats
  let runstats: NmapRunStats | undefined;
  if (nmaprun.runstats) {
    const finished = nmaprun.runstats.finished || {};
    const hostStats = nmaprun.runstats.hosts || {};
    runstats = {
      finished: {
        time: Number(finished['@_time']) || start,
        timestr: finished['@_timestr'] || '',
        elapsed: Number(finished['@_elapsed']) || 0,
        summary: finished['@_summary'] || '',
        exit: finished['@_exit'] || 'success',
      },
      hosts: {
        up: Number(hostStats['@_up']) || hosts.filter((h) => h.status.state === 'up').length,
        down: Number(hostStats['@_down']) || hosts.filter((h) => h.status.state === 'down').length,
        total: Number(hostStats['@_total']) || hosts.length,
      },
    };
  } else {
    runstats = {
      finished: {
        time: start,
        timestr: startstr,
        elapsed: 0,
        summary: `Nmap scan completed: ${hosts.length} hosts discovered`,
        exit: 'success',
      },
      hosts: {
        up: hosts.filter((h) => h.status.state === 'up').length,
        down: hosts.filter((h) => h.status.state === 'down').length,
        total: hosts.length,
      },
    };
  }

  return {
    scanner,
    args,
    start,
    startstr,
    version,
    xmloutputversion,
    scaninfo: scaninfoList.length > 0 ? scaninfoList : undefined,
    verbose,
    debugging,
    hosts,
    runstats,
    rawXml: xmlString,
  };
}
