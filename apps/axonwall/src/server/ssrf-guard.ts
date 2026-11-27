import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';

export interface SsrfGuardOptions {
  allowHttp?: boolean;
  allowPrivate?: boolean;
  maxResponseBytes?: number;
  resolveDns?: (
    hostname: string,
    options: { all: true; verbatim?: boolean }
  ) => Promise<Array<{ address: string; family: number }>>;
}

const DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024;

function expandIpv6Hextets(ip: string): number[] | null {
  const clean = ip.trim().replace(/^\[|\]$/g, '').split('%')[0]?.trim().toLowerCase() || '';
  if (!net.isIPv6(clean)) return null;

  let working = clean;
  // Convert embedded trailing IPv4 (e.g. ::ffff:127.0.0.1) to 2 hextets
  const lastColon = working.lastIndexOf(':');
  if (lastColon !== -1 && working.slice(lastColon + 1).includes('.')) {
    const v4Part = working.slice(lastColon + 1);
    if (!net.isIPv4(v4Part)) return null;
    const oct = v4Part.split('.').map((n) => Number(n));
    const hi = ((oct[0]! << 8) | oct[1]!).toString(16);
    const lo = ((oct[2]! << 8) | oct[3]!).toString(16);
    working = `${working.slice(0, lastColon + 1)}${hi}:${lo}`;
  }

  const parts = working.split('::');
  if (parts.length > 2) return null;

  const parseSide = (side: string): number[] | null => {
    if (!side) return [];
    const tokens = side.split(':');
    const out: number[] = [];
    for (const tok of tokens) {
      if (!/^[0-9a-f]{1,4}$/i.test(tok)) return null;
      out.push(parseInt(tok, 16));
    }
    return out;
  };

  const left = parseSide(parts[0] || '');
  const right = parts.length === 2 ? parseSide(parts[1] || '') : [];
  if (!left || !right) return null;

  if (parts.length === 1) {
    return left.length === 8 ? left : null;
  }

  const missing = 8 - (left.length + right.length);
  if (missing < 1) return null;
  return [...left, ...new Array<number>(missing).fill(0), ...right];
}

/**
 * Returns true if an IPv4/IPv6 literal targets loopback, link-local / cloud metadata,
 * unspecified, multicast, CGNAT, or (unless allowPrivate is true) private networks.
 */
export function isDisallowedSsrfIp(ip: string, options?: { allowPrivate?: boolean }): boolean {
  const clean = (ip || '').trim().replace(/^\[|\]$/g, '').split('%')[0]?.trim().toLowerCase() || '';
  if (!clean) return true;

  if (net.isIPv4(clean)) {
    const oct = clean.split('.').map((n) => Number(n));
    if (oct.length !== 4 || oct.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
      return true;
    }
    const [a, b] = oct as [number, number, number, number];
    // Always block 0.0.0.0/8 ("this" network), 169.254.0.0/16 (link-local / IMDS),
    // and 224.0.0.0/4+ (multicast / reserved / broadcast)
    if (a === 0 || (a === 169 && b === 254) || a >= 224) {
      return true;
    }
    if (!options?.allowPrivate) {
      if (a === 127) return true; // Loopback 127.0.0.0/8
      if (a === 10) return true; // RFC1918 10.0.0.0/8
      if (a === 172 && b >= 16 && b <= 31) return true; // RFC1918 172.16.0.0/12
      if (a === 192 && b === 168) return true; // RFC1918 192.168.0.0/16
      if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10
    }
    return false;
  }

  const h = expandIpv6Hextets(clean);
  if (!h) return true;

  // Unspecified ::/128
  if (h.every((x) => x === 0)) return true;
  // Always block AWS IPv6 IMDS endpoint fd00:ec2::254 even in private-network mode
  if (
    h[0] === 0xfd00 &&
    h[1] === 0x0ec2 &&
    h[2] === 0 &&
    h[3] === 0 &&
    h[4] === 0 &&
    h[5] === 0 &&
    h[6] === 0 &&
    h[7] === 0x0254
  ) {
    return true;
  }
  // Link-local fe80::/10, deprecated site-local fec0::/10, & multicast ff00::/8
  if ((h[0]! & 0xffc0) === 0xfe80 || (h[0]! & 0xffc0) === 0xfec0 || (h[0]! & 0xff00) === 0xff00) {
    return true;
  }

  // Transition / tunneling IPv6 prefixes that can smuggle or encapsulate private/loopback IPv4:
  // NAT64 local-use 64:ff9b:1::/48, 6to4 2002::/16, Teredo 2001::/32, SIIT ::ffff:0:0:0/96
  if (
    (h[0] === 0x0064 && h[1] === 0xff9b && h[2] === 0x0001) ||
    h[0] === 0x2002 ||
    (h[0] === 0x2001 && h[1] === 0x0000) ||
    (h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0xffff && h[5] === 0)
  ) {
    return true;
  }

  // IPv4-mapped ::ffff:0:0/96 or IPv4-compatible ::/96 (excluding ::1) or NAT64 64:ff9b::/96
  const isV4Mapped = h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0 && h[5] === 0xffff;
  const isV4Compat = h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0 && h[5] === 0 && !(h[6] === 0 && h[7] <= 1);
  const isNat64 = h[0] === 0x0064 && h[1] === 0xff9b && h[2] === 0 && h[3] === 0 && h[4] === 0 && h[5] === 0;
  if (isV4Mapped || isV4Compat || isNat64) {
    const mappedV4 = `${(h[6]! >> 8) & 0xff}.${h[6]! & 0xff}.${(h[7]! >> 8) & 0xff}.${h[7]! & 0xff}`;
    return isDisallowedSsrfIp(mappedV4, options);
  }

  if (!options?.allowPrivate) {
    // Loopback ::1/128
    if (h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0 && h[5] === 0 && h[6] === 0 && h[7] === 1) {
      return true;
    }
    // Unique Local Addresses fc00::/7 (both fc00::/8 and fd00::/8)
    if ((h[0]! & 0xfe00) === 0xfc00) {
      return true;
    }
  }

  return false;
}

/**
 * Returns true when the IP literal is a loopback address (127.0.0.0/8, ::1, or IPv4-mapped loopback).
 */
export function isLoopbackSsrfIp(ip: string): boolean {
  const clean = (ip || '').trim().replace(/^\[|\]$/g, '').split('%')[0]?.trim().toLowerCase() || '';
  if (!clean) return false;
  if (net.isIPv4(clean)) {
    return clean.startsWith('127.');
  }
  const h = expandIpv6Hextets(clean);
  if (!h) return false;
  if (h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0 && h[5] === 0 && h[6] === 0 && h[7] === 1) {
    return true;
  }
  const isV4Mapped = h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0 && h[5] === 0xffff;
  if (isV4Mapped) {
    return ((h[6]! >> 8) & 0xff) === 127;
  }
  return false;
}

/**
 * Builds a Node DNS lookup callback pinned to validated addresses from assertSafeOutboundUrl.
 */
export function createPinnedLookup(
  addresses: Array<{ address: string; family: number }>
): (hostname: string, opts: any, cb?: any) => void {
  const pinned = addresses[0]!;
  return (_hostname: string, opts: any, cb?: any) => {
    const callback = typeof opts === 'function' ? opts : cb;
    if (typeof callback !== 'function') return;
    if (opts && typeof opts === 'object' && opts.all) {
      callback(
        null,
        addresses.map((a) => ({ address: a.address, family: a.family }))
      );
    } else {
      callback(null, pinned.address, pinned.family);
    }
  };
}

const BLOCKED_METADATA_HOSTS = new Set([
  'metadata.google.internal',
  'metadata.goog',
  'metadata',
  'instance-data',
]);

export async function assertSafeOutboundUrl(
  rawUrl: string,
  options?: SsrfGuardOptions
): Promise<{ url: URL; addresses: Array<{ address: string; family: number }> }> {
  let url: URL;
  try {
    url = new URL(rawUrl.trim());
  } catch {
    throw new Error('Invalid endpoint URL');
  }

  if (url.username || url.password) {
    throw new Error('URLs with embedded credentials are not permitted');
  }

  if (url.protocol !== 'https:' && !(options?.allowHttp && url.protocol === 'http:')) {
    throw new Error(
      options?.allowHttp
        ? 'Endpoint must use http: or https:'
        : 'Remote endpoints must use HTTPS'
    );
  }

  const host = url.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  if (!host) {
    throw new Error('Endpoint URL is missing a hostname');
  }

  if (BLOCKED_METADATA_HOSTS.has(host)) {
    throw new Error('Access to cloud metadata or link-local endpoints is prohibited');
  }

  if (!options?.allowPrivate && (host === 'localhost' || host.endsWith('.localhost'))) {
    throw new Error('Remote endpoints cannot target loopback or private networks');
  }

  const ipVer = net.isIP(host);
  if (ipVer !== 0) {
    if (isDisallowedSsrfIp(host, options)) {
      throw new Error(
        options?.allowPrivate
          ? 'Access to cloud metadata or link-local endpoints is prohibited'
          : 'Remote endpoints cannot target loopback, link-local, or private networks'
      );
    }
    return { url, addresses: [{ address: host, family: ipVer }] };
  }

  const resolver =
    options?.resolveDns ??
    ((hostname, opts) => dns.promises.lookup(hostname, opts) as Promise<Array<{ address: string; family: number }>>);

  let records: Array<{ address: string; family: number }>;
  try {
    records = await resolver(host, { all: true, verbatim: true });
  } catch (err: any) {
    throw new Error(`DNS resolution failed for ${host}: ${err?.message || 'unknown error'}`);
  }

  if (!Array.isArray(records) || records.length === 0) {
    throw new Error(`DNS resolution returned no addresses for ${host}`);
  }

  for (const rec of records) {
    if (!rec?.address || isDisallowedSsrfIp(rec.address, options)) {
      throw new Error(
        options?.allowPrivate
          ? `Resolved address '${rec?.address || ''}' is prohibited (link-local or metadata range)`
          : `Resolved address '${rec?.address || ''}' is prohibited (loopback, link-local, or private range)`
      );
    }
  }

  return {
    url,
    addresses: records.map((r) => ({
      address: r.address,
      family: r.family === 6 || net.isIPv6(r.address) ? 6 : 4,
    })),
  };
}

export interface SsrfSafeResponse {
  ok: boolean;
  status: number;
  statusText: string;
  headers: Record<string, string | string[] | undefined>;
  text(): Promise<string>;
  json<T = any>(): Promise<T>;
}

/**
 * Performs an HTTP(S) request after DNS/IP SSRF validation, pins the TCP connection to the
 * validated IP address (preventing DNS rebinding), and refuses all 3xx HTTP redirects.
 */
export async function ssrfSafeFetch(
  rawUrl: string,
  init: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    signal?: AbortSignal;
    timeoutMs?: number;
    maxResponseBytes?: number;
  } = {},
  options?: SsrfGuardOptions
): Promise<SsrfSafeResponse> {
  const { url, addresses } = await assertSafeOutboundUrl(rawUrl, options);
  const maxBytesRaw = init.maxResponseBytes ?? options?.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  const maxResponseBytes =
    typeof maxBytesRaw === 'number' && Number.isFinite(maxBytesRaw) && maxBytesRaw > 0
      ? Math.floor(maxBytesRaw)
      : DEFAULT_MAX_RESPONSE_BYTES;
  const pinnedLookup = createPinnedLookup(addresses);
  const isHttps = url.protocol === 'https:';
  const transport = isHttps ? https : http;
  const hostHeader = url.port ? `${url.hostname}:${url.port}` : url.hostname;
  const reqHeaders: Record<string, string> = {
    ...(init.headers || {}),
    Host: hostHeader,
  };
  if (init.body !== undefined && !Object.keys(reqHeaders).some((k) => k.toLowerCase() === 'content-length')) {
    reqHeaders['Content-Length'] = Buffer.byteLength(init.body, 'utf8').toString();
  }

  return new Promise<SsrfSafeResponse>((resolve, reject) => {
    let settled = false;
    const fail = (err: Error) => {
      if (settled) return;
      settled = true;
      init.signal?.removeEventListener('abort', onAbort);
      reject(err);
    };

    if (init.signal?.aborted) {
      reject(new Error('Request aborted'));
      return;
    }

    const req = transport.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port ? Number(url.port) : isHttps ? 443 : 80,
        path: `${url.pathname}${url.search}`,
        method: init.method || 'GET',
        headers: reqHeaders,
        timeout: init.timeoutMs ?? 15000,
        ...(isHttps ? { servername: url.hostname.replace(/^\[|\]$/g, '') } : {}),
        lookup: pinnedLookup,
      },
      (res) => {
        const status = res.statusCode || 0;
        if (status >= 300 && status < 400) {
          res.resume();
          fail(new Error(`Outbound HTTP redirect (${status}) blocked by SSRF policy`));
          return;
        }
        const contentLengthHeader = res.headers['content-length'];
        const declaredLen =
          typeof contentLengthHeader === 'string'
            ? Number(contentLengthHeader)
            : Array.isArray(contentLengthHeader)
              ? Number(contentLengthHeader[0])
              : NaN;
        if (Number.isFinite(declaredLen) && declaredLen > maxResponseBytes) {
          res.destroy();
          req.destroy();
          fail(new Error(`Outbound response exceeded maxResponseBytes limit (${maxResponseBytes} bytes)`));
          return;
        }

        const chunks: Buffer[] = [];
        let totalBytes = 0;
        res.on('data', (chunk: Buffer) => {
          const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          totalBytes += buf.length;
          if (totalBytes > maxResponseBytes) {
            res.destroy();
            req.destroy();
            fail(new Error(`Outbound response exceeded maxResponseBytes limit (${maxResponseBytes} bytes)`));
            return;
          }
          chunks.push(buf);
        });
        res.on('error', (err) => fail(err instanceof Error ? err : new Error(String(err))));
        res.on('end', () => {
          if (settled) return;
          settled = true;
          init.signal?.removeEventListener('abort', onAbort);
          const rawText = Buffer.concat(chunks).toString('utf8');
          resolve({
            ok: status >= 200 && status < 300,
            status,
            statusText: res.statusMessage || '',
            headers: res.headers,
            text: async () => rawText,
            json: async <T = any>() => JSON.parse(rawText) as T,
          });
        });
      }
    );

    const onAbort = () => {
      const err = new Error('Request aborted');
      req.destroy(err);
      fail(err);
    };
    init.signal?.addEventListener('abort', onAbort, { once: true });

    req.on('timeout', () => {
      const err = new Error('Outbound request timed out');
      req.destroy(err);
      fail(err);
    });
    req.on('error', (err) => {
      fail(err instanceof Error ? err : new Error(String(err)));
    });
    req.on('close', () => {
      init.signal?.removeEventListener('abort', onAbort);
    });

    if (init.body !== undefined) {
      req.write(init.body, 'utf8');
    }
    req.end();
  });
}
