import dns from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';

export const DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024; // 10 MB

const METADATA_HOSTNAMES = new Set([
  'metadata.google.internal',
  'metadata.goog',
  'metadata',
  'instance-data',
  '169.254.169.254'
]);

/**
 * Parse a dotted IPv4 address into an unsigned 32-bit integer, or null.
 */
export function parseIpv4Int(ip) {
  const parts = String(ip).split('.');
  if (parts.length !== 4) return null;
  let val = 0;
  for (const p of parts) {
    if (!/^\d+$/.test(p)) return null;
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    val = ((val << 8) | n) >>> 0;
  }
  return val;
}

/**
 * Parse any canonical or compressed IPv6 string (including dotted IPv4-mapped)
 * into a 128-bit BigInt, or null if invalid.
 */
export function parseIpv6BigInt(ip) {
  let clean = String(ip || '').replace(/^\[|\]$/g, '').split('%')[0].toLowerCase();
  if (!clean) return null;

  if (clean.includes('.')) {
    const lastColon = clean.lastIndexOf(':');
    if (lastColon === -1) return null;
    const v4Int = parseIpv4Int(clean.slice(lastColon + 1));
    if (v4Int === null) return null;
    const hi = ((v4Int >>> 16) & 0xffff).toString(16);
    const lo = (v4Int & 0xffff).toString(16);
    clean = `${clean.slice(0, lastColon)}:${hi}:${lo}`;
  }

  const halves = clean.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = halves.length === 2 ? 8 - (left.length + right.length) : 0;
  if (missing < 0 || (halves.length === 1 && left.length !== 8)) return null;
  const groups = [...left, ...Array(missing).fill('0'), ...right];
  if (groups.length !== 8) return null;

  let val = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    val = (val << 16n) | BigInt(parseInt(g, 16));
  }
  return val;
}

/**
 * Check whether an IPv4 or IPv6 address falls in metadata/link-local,
 * loopback, RFC1918, ULA, CGNAT, or reserved/multicast ranges.
 */
export function classifyIpRange(ip) {
  const raw = String(ip || '').replace(/^\[|\]$/g, '').split('%')[0].trim();
  const family = net.isIP(raw);
  if (family === 4) {
    const v4 = parseIpv4Int(raw);
    if (v4 === null) return 'invalid';
    const a = (v4 >>> 24) & 0xff;
    const b = (v4 >>> 16) & 0xff;
    const c = (v4 >>> 8) & 0xff;
    if (a === 0) return 'unspecified';
    if (a === 169 && b === 254) return 'metadata'; // link-local / cloud IMDS
    if (a === 127) return 'loopback';
    if (a === 10) return 'private';
    if (a === 172 && b >= 16 && b <= 31) return 'private';
    if (a === 192 && b === 168) return 'private';
    if (a === 100 && b >= 64 && b <= 127) return 'private'; // CGNAT RFC6598
    if (a === 198 && (b === 18 || b === 19)) return 'reserved'; // benchmarking RFC2544
    if (a === 192 && b === 88 && c === 99) return 'reserved'; // 6to4 relay anycast RFC7526
    if (a === 192 && b === 0) return 'reserved';
    if (a >= 224) return 'reserved'; // multicast / Class E / broadcast
    return 'public';
  }
  if (family === 6) {
    const v6 = parseIpv6BigInt(raw);
    if (v6 === null) return 'invalid';
    const intToDottedV4 = (v4) =>
      `${(v4 >>> 24) & 0xff}.${(v4 >>> 16) & 0xff}.${(v4 >>> 8) & 0xff}.${v4 & 0xff}`;
    // Unwrap IPv4-mapped ::ffff:0:0/96 (both dotted ::ffff:a.b.c.d and hex ::ffff:a9fe:a9fe)
    if ((v6 >> 32n) === 0xffffn) {
      return classifyIpRange(intToDottedV4(Number(v6 & 0xffffffffn)));
    }
    // Block SIIT ::ffff:0:0:0/96 (RFC 2765) and unwrap embedded IPv4
    if ((v6 >> 32n) === 0xffff0000n) {
      const cls = classifyIpRange(intToDottedV4(Number(v6 & 0xffffffffn)));
      return cls === 'metadata' ? 'metadata' : 'reserved';
    }
    // Unwrap deprecated IPv4-compatible ::/96 when non-loopback/unspecified
    if ((v6 >> 32n) === 0n && v6 > 1n) {
      return classifyIpRange(intToDottedV4(Number(v6 & 0xffffffffn)));
    }
    // Unwrap NAT64 64:ff9b::/96 (RFC 6052 Well-Known Prefix)
    if ((v6 >> 32n) === 0x0064ff9b0000000000000000n) {
      return classifyIpRange(intToDottedV4(Number(v6 & 0xffffffffn)));
    }
    // Block NAT64 local-use 64:ff9b:1::/48 (RFC 8215)
    if ((v6 >> 80n) === 0x0064ff9b0001n) {
      if ((v6 >> 32n) === 0x0064ff9b0001000000000000n) {
        const cls = classifyIpRange(intToDottedV4(Number(v6 & 0xffffffffn)));
        if (cls === 'metadata') return 'metadata';
      }
      return 'reserved';
    }
    // Block 6to4 2002::/16 (RFC 3056 / RFC 7526) and unwrap embedded IPv4
    if ((v6 >> 112n) === 0x2002n) {
      const cls = classifyIpRange(intToDottedV4(Number((v6 >> 80n) & 0xffffffffn)));
      return cls === 'metadata' ? 'metadata' : 'reserved';
    }
    // Block Teredo 2001::/32 (RFC 4380) and Documentation 2001:db8::/32 (RFC 3849)
    if ((v6 >> 96n) === 0x20010000n || (v6 >> 96n) === 0x20010db8n) {
      return 'reserved';
    }
    // Block Discard-Only 100::/64 (RFC 6666)
    if ((v6 >> 64n) === 0x0100000000000000n) {
      return 'reserved';
    }
    if (v6 === 0n) return 'unspecified';
    if (v6 === 1n) return 'loopback';
    // fe80::/10 link-local
    if ((v6 >> 118n) === 0x3fan) return 'metadata';
    // fec0::/10 deprecated site-local (RFC 3879)
    if ((v6 >> 118n) === 0x3fbn) return 'reserved';
    // fc00::/7 Unique Local Address (includes AWS IPv6 IMDS fd00:ec2::254)
    if ((v6 >> 121n) === 0x7en) {
      // fd00:ec2::254 specifically is AWS EC2 IPv6 IMDS
      const awsImds6 = 0xfd000ec2000000000000000000000254n;
      if (v6 === awsImds6) return 'metadata';
      return 'private';
    }
    // ff00::/8 multicast
    if ((v6 >> 120n) === 0xffn) return 'reserved';
    return 'public';
  }
  return 'unknown';
}

function assertIpAllowed(ip, { allowPrivate = false, allowLoopback = false, allowMetadata = false }, label) {
  const cls = classifyIpRange(ip);
  if (cls === 'public') return;
  if (cls === 'metadata' && allowMetadata) return;
  if (cls === 'loopback' && allowLoopback) return;
  if (cls === 'private' && allowPrivate) return;
  throw new Error(`Blocked SSRF ${label}: address '${ip}' (${cls}) is not permitted`);
}

/**
 * Shared outbound target validation (SSRF guard) across HTTP probes, OIDC, scanners, and diagnostics.
 * Parses URL or bare host, canonicalizes IPv4/IPv6 (including hex ::ffff: unwrapping), resolves DNS,
 * and blocks IMDS/link-local, RFC1918/ULA, loopback, and reserved ranges unless explicitly permitted.
 *
 * @param {string} targetRaw
 * @param {Object} [options={}]
 * @returns {Promise<{ url: URL, hostname: string, isIp: boolean, addresses: string[] }>}
 */
export async function assertSafeOutboundTarget(targetRaw, options = {}) {
  const {
    label = 'target',
    allowedProtocols = ['http:', 'https:'],
    allowBareHost = false,
    allowHttpOnlyForLoopback = false,
    allowPrivate = process.env.VIGILANTE_ALLOW_PRIVATE_TARGETS === '1',
    allowLoopback = false,
    allowMetadata = false,
    failOnDnsError = true,
    dnsLookup = dns.lookup
  } = options;

  const raw = String(targetRaw ?? '').trim();
  if (!raw) {
    throw new Error(`Invalid ${label}: empty target`);
  }

  let parsed;
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw)) {
    parsed = new URL(raw);
  } else if (allowBareHost) {
    const bare = raw.replace(/^\[|\]$/g, '');
    const bracketedMatch = raw.match(/^\[([^\]]+)\](?::\d+)?(?:[/?#]|$)/);
    if (bracketedMatch) {
      if (net.isIP(bracketedMatch[1]) !== 6) {
        throw new Error(`Invalid ${label} '${targetRaw}'`);
      }
      parsed = new URL(`http://${raw}`);
    } else if (net.isIP(bare) === 6) {
      parsed = new URL(`http://[${bare}]`);
    } else if (/^[a-zA-Z0-9.-]+:\d+(?:[/?#]|$)/.test(raw) || net.isIP(bare) === 4 || /^[a-zA-Z0-9.-]+(?:[/?#]|$)/.test(raw)) {
      parsed = new URL(`http://${raw}`);
    } else {
      throw new Error(`Invalid ${label} '${targetRaw}'`);
    }
  } else {
    parsed = new URL(raw);
  }

  if (!allowedProtocols.includes(parsed.protocol)) {
    throw new Error(`Disallowed ${label} protocol '${parsed.protocol}'`);
  }

  const rawHost = parsed.hostname.replace(/^\[|\]$/g, '').split('%')[0].replace(/\.+$/, '').toLowerCase();
  if (!rawHost) {
    throw new Error(`Invalid ${label}: missing hostname`);
  }

  const isLocalhostName = rawHost === 'localhost' || rawHost.endsWith('.localhost');
  if (allowHttpOnlyForLoopback && parsed.protocol === 'http:') {
    const cls = net.isIP(rawHost) ? classifyIpRange(rawHost) : (isLocalhostName ? 'loopback' : null);
    if (cls !== 'loopback') {
      throw new Error(`Unsafe ${label} protocol '${parsed.protocol}': HTTPS required for non-loopback hosts`);
    }
  }

  if (METADATA_HOSTNAMES.has(rawHost) && !allowMetadata) {
    throw new Error(`Blocked SSRF ${label}: metadata hostname '${rawHost}' is forbidden`);
  }

  if (isLocalhostName && !allowLoopback) {
    throw new Error(`Blocked SSRF ${label}: loopback hostname '${rawHost}' is forbidden`);
  }

  const ipFamily = net.isIP(rawHost);
  if (ipFamily !== 0) {
    assertIpAllowed(rawHost, { allowPrivate, allowLoopback, allowMetadata }, label);
    return { url: parsed, hostname: rawHost, isIp: true, addresses: [rawHost] };
  }

  let resolved = [];
  try {
    const records = await dnsLookup(rawHost, { all: true });
    resolved = Array.isArray(records)
      ? records.map(r => (typeof r === 'string' ? r : r.address)).filter(Boolean)
      : (records?.address ? [records.address] : []);
  } catch (err) {
    if (failOnDnsError) {
      throw new Error(`DNS resolution failed for ${label} '${rawHost}': ${err.message}`);
    }
    return { url: parsed, hostname: rawHost, isIp: false, addresses: [] };
  }

  if (resolved.length === 0 && failOnDnsError) {
    throw new Error(`DNS resolution returned no addresses for ${label} '${rawHost}'`);
  }

  for (const addr of resolved) {
    assertIpAllowed(addr, { allowPrivate, allowLoopback, allowMetadata }, label);
  }

  return { url: parsed, hostname: rawHost, isIp: false, addresses: resolved };
}

/**
 * Build a Node.js `dns.lookup` callback pinned to validated IP addresses
 * returned by `assertSafeOutboundTarget()`, eliminating DNS rebinding TOCTOU.
 *
 * @param {Array<string|{ address: string, family?: number }>} addresses
 * @returns {(hostname: string, opts: any, cb?: Function) => void}
 */
export function createPinnedLookup(addresses) {
  const list = (Array.isArray(addresses) ? addresses : [addresses])
    .map((entry) => {
      const raw = typeof entry === 'string' ? entry : entry?.address;
      if (!raw) return null;
      const address = String(raw).replace(/^\[|\]$/g, '').split('%')[0].trim();
      if (!address) return null;
      const family = (typeof entry === 'object' && (entry.family === 4 || entry.family === 6))
        ? entry.family
        : (net.isIPv6(address) ? 6 : 4);
      return { address, family };
    })
    .filter(Boolean);

  if (list.length === 0) {
    throw new Error('createPinnedLookup requires at least one validated IP address');
  }

  return (_hostname, opts, cb) => {
    let callback = cb;
    let lookupOpts = opts;
    if (typeof opts === 'function') {
      callback = opts;
      lookupOpts = {};
    }
    if (typeof callback !== 'function') return;

    const requestedFamily =
      lookupOpts && typeof lookupOpts === 'object' && (lookupOpts.family === 4 || lookupOpts.family === 6)
        ? lookupOpts.family
        : 0;
    const filtered = requestedFamily ? list.filter((a) => a.family === requestedFamily) : list;
    const candidates = filtered.length > 0 ? filtered : list;

    if (lookupOpts && typeof lookupOpts === 'object' && lookupOpts.all) {
      queueMicrotask(() => {
        callback(null, candidates.map((a) => ({ address: a.address, family: a.family })));
      });
    } else {
      const first = candidates[0];
      queueMicrotask(() => {
        callback(null, first.address, first.family);
      });
    }
  };
}

/**
 * Read a Fetch Response (or Node IncomingMessage) body with a strict byte cap,
 * aborting the underlying stream immediately if `maxBytes` is exceeded.
 *
 * @param {Response|import('node:http').IncomingMessage} res
 * @param {number} [maxBytes=DEFAULT_MAX_RESPONSE_BYTES]
 * @returns {Promise<string>}
 */
export async function readResponseWithLimit(res, maxBytes = DEFAULT_MAX_RESPONSE_BYTES) {
  if (!res) {
    throw new Error('Response object is required');
  }
  const limit = Number.isFinite(Number(maxBytes)) && Number(maxBytes) > 0
    ? Math.floor(Number(maxBytes))
    : DEFAULT_MAX_RESPONSE_BYTES;

  const rawLen = typeof res.headers?.get === 'function'
    ? res.headers.get('content-length')
    : res.headers?.['content-length'];
  const declaredLen = rawLen !== null && rawLen !== undefined && rawLen !== ''
    ? Number(Array.isArray(rawLen) ? rawLen[0] : rawLen)
    : NaN;
  if (Number.isFinite(declaredLen) && declaredLen > limit) {
    await res.body?.cancel?.().catch(() => {});
    if (typeof res.destroy === 'function') res.destroy();
    throw new Error(`Response body exceeded maximum allowed size (${limit} bytes)`);
  }

  if (res.body && typeof res.body.getReader === 'function') {
    const reader = res.body.getReader();
    const chunks = [];
    let totalBytes = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          totalBytes += value.byteLength;
          if (totalBytes > limit) {
            await reader.cancel().catch(() => {});
            throw new Error(`Response body exceeded maximum allowed size (${limit} bytes)`);
          }
          chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
        }
      }
    } finally {
      reader.releaseLock();
    }
    return Buffer.concat(chunks).toString('utf8');
  }

  if (typeof res[Symbol.asyncIterator] === 'function') {
    const chunks = [];
    let totalBytes = 0;
    for await (const chunk of res) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      totalBytes += buf.length;
      if (totalBytes > limit) {
        if (typeof res.destroy === 'function') res.destroy();
        throw new Error(`Response body exceeded maximum allowed size (${limit} bytes)`);
      }
      chunks.push(buf);
    }
    return Buffer.concat(chunks).toString('utf8');
  }

  if (typeof res.text === 'function') {
    const text = await res.text();
    if (Buffer.byteLength(text, 'utf8') > limit) {
      throw new Error(`Response body exceeded maximum allowed size (${limit} bytes)`);
    }
    return text;
  }

  return '';
}

function normalizeFetchHeaders(headersInput) {
  const out = {};
  if (!headersInput) return out;
  const hdrs = new Headers(headersInput);
  for (const [k, v] of hdrs.entries()) {
    out[k] = v;
  }
  return out;
}

function performPinnedHttpRequest(parsedUrl, addresses, init, maxBytes, opts) {
  const isHttps = parsedUrl.protocol === 'https:';
  const transport = isHttps ? https : http;
  const cleanHost = parsedUrl.hostname.replace(/^\[|\]$/g, '');
  const port = parsedUrl.port ? Number(parsedUrl.port) : (isHttps ? 443 : 80);
  const method = String(init?.method || 'GET').toUpperCase();
  const headers = normalizeFetchHeaders(init?.headers);
  if (!Object.keys(headers).some((k) => k.toLowerCase() === 'host')) {
    headers.Host = parsedUrl.host;
  }

  let bodyBuf = null;
  if (init?.body !== undefined && init?.body !== null) {
    if (Buffer.isBuffer(init.body) || init.body instanceof Uint8Array) {
      bodyBuf = Buffer.from(init.body);
    } else if (typeof init.body === 'string') {
      bodyBuf = Buffer.from(init.body, 'utf8');
    } else {
      bodyBuf = Buffer.from(String(init.body), 'utf8');
    }
    if (!Object.keys(headers).some((k) => k.toLowerCase() === 'content-length')) {
      headers['Content-Length'] = String(bodyBuf.length);
    }
  }

  const lookup = createPinnedLookup(addresses);
  const timeoutMs = init?.timeoutMs ?? opts?.timeoutMs;
  const signal = init?.signal;

  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason || new Error('Request aborted'));
      return;
    }

    let settled = false;
    const fail = (err) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener('abort', onAbort);
      reject(err);
    };

    const req = transport.request(
      {
        protocol: parsedUrl.protocol,
        hostname: cleanHost,
        port,
        path: `${parsedUrl.pathname}${parsedUrl.search}`,
        method,
        headers,
        lookup,
        ...(isHttps && !net.isIP(cleanHost) ? { servername: cleanHost } : {}),
        ...(isHttps && opts?.rejectUnauthorized !== undefined ? { rejectUnauthorized: opts.rejectUnauthorized } : {})
      },
      (nodeRes) => {
        const status = nodeRes.statusCode || 0;
        const rawLen = nodeRes.headers['content-length'];
        const declaredLen = rawLen !== undefined
          ? Number(Array.isArray(rawLen) ? rawLen[0] : rawLen)
          : NaN;
        if (Number.isFinite(declaredLen) && declaredLen > maxBytes) {
          nodeRes.destroy();
          req.destroy();
          fail(new Error(`Response body exceeded maximum allowed size (${maxBytes} bytes)`));
          return;
        }

        const respHeaders = new Headers();
        for (const [k, v] of Object.entries(nodeRes.headers)) {
          if (v === undefined) continue;
          if (Array.isArray(v)) {
            for (const item of v) respHeaders.append(k, item);
          } else {
            respHeaders.set(k, String(v));
          }
        }

        const isNullBody = method === 'HEAD' || [101, 204, 205, 304].includes(status);
        let bodyStream = null;
        if (isNullBody) {
          nodeRes.resume();
        } else {
          bodyStream = new ReadableStream({
            start(controller) {
              let totalBytes = 0;
              let closed = false;
              const onStreamAbort = () => {
                if (closed) return;
                closed = true;
                const err = signal?.reason || new Error('Request aborted');
                nodeRes.destroy(err);
                try { controller.error(err); } catch {}
              };
              signal?.addEventListener('abort', onStreamAbort, { once: true });

              nodeRes.on('data', (chunk) => {
                if (closed) return;
                const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
                totalBytes += buf.length;
                if (totalBytes > maxBytes) {
                  closed = true;
                  signal?.removeEventListener('abort', onStreamAbort);
                  const err = new Error(`Response body exceeded maximum allowed size (${maxBytes} bytes)`);
                  nodeRes.destroy(err);
                  controller.error(err);
                  return;
                }
                controller.enqueue(new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength));
                if (controller.desiredSize !== null && controller.desiredSize <= 0) {
                  nodeRes.pause();
                }
              });
              nodeRes.on('end', () => {
                if (closed) return;
                closed = true;
                signal?.removeEventListener('abort', onStreamAbort);
                controller.close();
              });
              nodeRes.on('error', (err) => {
                if (closed) return;
                closed = true;
                signal?.removeEventListener('abort', onStreamAbort);
                controller.error(err);
              });
            },
            pull() {
              nodeRes.resume();
            },
            cancel() {
              nodeRes.destroy();
            }
          });
        }

        if (settled) return;
        settled = true;
        signal?.removeEventListener('abort', onAbort);
        const response = new Response(bodyStream, {
          status,
          statusText: nodeRes.statusMessage || '',
          headers: respHeaders
        });
        Object.defineProperty(response, 'url', { value: parsedUrl.toString() });
        resolve(response);
      }
    );

    const onAbort = () => {
      const err = signal?.reason || new Error('Request aborted');
      req.destroy(err);
      fail(err);
    };
    signal?.addEventListener('abort', onAbort, { once: true });

    if (typeof timeoutMs === 'number' && Number.isFinite(timeoutMs) && timeoutMs > 0) {
      req.setTimeout(timeoutMs, () => {
        const err = new Error(`Outbound request timed out after ${timeoutMs}ms`);
        req.destroy(err);
        fail(err);
      });
    }

    req.on('error', (err) => {
      fail(err instanceof Error ? err : new Error(String(err)));
    });

    if (bodyBuf) {
      req.write(bodyBuf);
    }
    req.end();
  });
}

/**
 * SSRF-hardened HTTP(S) fetch:
 * 1. Validates target URL & DNS via `assertSafeOutboundTarget()`.
 * 2. Pins TCP socket DNS resolution via `createPinnedLookup()` (preserving TLS SNI & Host).
 * 3. Defaults `redirect` to `'error'` (or re-validates every hop when `redirect === 'follow'`).
 * 4. Caps response bodies to `maxBytes` (default 10 MB) at both headers & stream level.
 *
 * @param {string} url
 * @param {RequestInit & { maxBytes?: number, maxResponseBytes?: number, timeoutMs?: number }} [init={}]
 * @param {Object} [opts={}]
 * @returns {Promise<Response>}
 */
export async function safeFetch(url, init = {}, opts = {}) {
  const redirectMode = init?.redirect || opts?.redirect || 'error';
  const maxBytesRaw = init?.maxBytes ?? init?.maxResponseBytes ?? opts?.maxBytes ?? opts?.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  const maxBytes = Number.isFinite(Number(maxBytesRaw)) && Number(maxBytesRaw) > 0
    ? Math.floor(Number(maxBytesRaw))
    : DEFAULT_MAX_RESPONSE_BYTES;
  const maxRedirects = Number.isInteger(opts?.maxRedirects) && opts.maxRedirects >= 0 ? opts.maxRedirects : 5;
  const label = opts?.label || 'target';

  let currentUrl = url;
  let currentInit = { ...init };
  let prevalidated = opts?.validatedTarget || null;

  for (let hop = 0; hop <= maxRedirects; hop++) {
    let targetInfo;
    if (prevalidated && hop === 0) {
      const requestedUrl = new URL(currentUrl);
      if (
        requestedUrl.protocol !== prevalidated.url.protocol ||
        requestedUrl.host !== prevalidated.url.host
      ) {
        targetInfo = await assertSafeOutboundTarget(currentUrl, opts);
      } else {
        if (!Array.isArray(prevalidated.addresses) || prevalidated.addresses.length === 0) {
          throw new Error(`No validated IP addresses available for ${label}`);
        }
        for (const addr of prevalidated.addresses) {
          assertIpAllowed(addr, {
            allowPrivate: opts?.allowPrivate ?? (process.env.VIGILANTE_ALLOW_PRIVATE_TARGETS === '1'),
            allowLoopback: opts?.allowLoopback ?? false,
            allowMetadata: opts?.allowMetadata ?? false
          }, label);
        }
        targetInfo = { ...prevalidated, url: requestedUrl };
      }
    } else {
      targetInfo = await assertSafeOutboundTarget(currentUrl, opts);
    }

    const res = await performPinnedHttpRequest(targetInfo.url, targetInfo.addresses, currentInit, maxBytes, opts);
    const isRedirect = res.status >= 300 && res.status < 400;
    if (!isRedirect) {
      return res;
    }

    if (redirectMode === 'manual') {
      return res;
    }

    const location = res.headers.get('location');
    await res.body?.cancel?.().catch(() => {});

    if (redirectMode !== 'follow') {
      throw new Error(`Blocked SSRF ${label}: outbound HTTP redirect (${res.status}) is not permitted`);
    }

    if (!location) {
      throw new Error(`Invalid redirect response (${res.status}) without Location header`);
    }
    if (hop >= maxRedirects) {
      throw new Error(`Exceeded maximum redirects (${maxRedirects})`);
    }

    const nextParsed = new URL(location, targetInfo.url);
    if (nextParsed.origin !== targetInfo.url.origin && currentInit.headers) {
      const stripped = new Headers(currentInit.headers);
      stripped.delete('authorization');
      stripped.delete('cookie');
      currentInit = { ...currentInit, headers: stripped };
    }
    currentUrl = nextParsed.toString();
  }

  throw new Error(`Exceeded maximum redirects (${maxRedirects})`);
}

function ipv4CidrBounds(ipInt, prefix) {
  const mask = prefix === 0 ? 0 : ((0xffffffff << (32 - prefix)) >>> 0);
  const start = (ipInt & mask) >>> 0;
  const end = (start | (~mask >>> 0)) >>> 0;
  return [start, end];
}

function ipv4RangesOverlap(aStart, aEnd, bStart, bEnd) {
  return aStart <= bEnd && aEnd >= bStart;
}

function ipv6CidrBounds(v6Int, prefix) {
  const allOnes = (1n << 128n) - 1n;
  const shift = 128n - BigInt(prefix);
  const mask = prefix === 0 ? 0n : ((allOnes << shift) & allOnes);
  const start = v6Int & mask;
  const end = start | (allOnes ^ mask);
  return [start, end];
}

function ipv6RangesOverlap(aStart, aEnd, bStart, bEnd) {
  return aStart <= bEnd && aEnd >= bStart;
}

const IPV4_OCTET_SPEC_RE = /^(?:\*|\d{1,3}(?:-\d{1,3})?|-\d{1,3}|\d{1,3}-)(?:,(?:\*|\d{1,3}(?:-\d{1,3})?|-\d{1,3}|\d{1,3}-))*$/;

function parseIpv4OctetValues(spec) {
  const set = new Uint8Array(256);
  for (const part of spec.split(',')) {
    if (part === '*') {
      set.fill(1);
      continue;
    }
    const dashIdx = part.indexOf('-');
    if (dashIdx === -1) {
      const n = Number(part);
      if (!Number.isInteger(n) || n < 0 || n > 255) return null;
      set[n] = 1;
    } else {
      const loStr = part.slice(0, dashIdx);
      const hiStr = part.slice(dashIdx + 1);
      const lo = loStr === '' ? 0 : Number(loStr);
      const hi = hiStr === '' ? 255 : Number(hiStr);
      if (!Number.isInteger(lo) || !Number.isInteger(hi) || lo < 0 || hi > 255 || lo > hi) return null;
      for (let v = lo; v <= hi; v++) set[v] = 1;
    }
  }
  return set;
}

function isSingleIpv4OctetPattern(token) {
  const parts = token.split('.');
  return parts.length === 4 && parts.every((p) => IPV4_OCTET_SPEC_RE.test(p));
}

function assertIpv4ScanBoundsAllowed(oct0, oct1, oct2, rawToken, { allowPrivate, allowLoopback, allowMetadata }, label) {
  const anyIn = (arr, lo, hi) => {
    for (let v = lo; v <= hi; v++) if (arr[v]) return true;
    return false;
  };
  if (oct0[169] && oct1[254] && !allowMetadata) {
    throw new Error(`Blocked SSRF ${label}: scan target '${rawToken}' covers metadata/link-local range 169.254.0.0/16`);
  }
  if (oct0[0]) {
    throw new Error(`Blocked SSRF ${label}: scan target '${rawToken}' covers unspecified range 0.0.0.0/8`);
  }
  if (oct0[198] && (oct1[18] || oct1[19])) {
    throw new Error(`Blocked SSRF ${label}: scan target '${rawToken}' covers reserved range 198.18.0.0/15`);
  }
  if (oct0[192] && oct1[88] && oct2[99]) {
    throw new Error(`Blocked SSRF ${label}: scan target '${rawToken}' covers reserved range 192.88.99.0/24`);
  }
  if (oct0[192] && oct1[0]) {
    throw new Error(`Blocked SSRF ${label}: scan target '${rawToken}' covers reserved range 192.0.0.0/16`);
  }
  if (anyIn(oct0, 224, 255)) {
    throw new Error(`Blocked SSRF ${label}: scan target '${rawToken}' covers reserved/multicast range 224.0.0.0/4`);
  }
  if (!allowLoopback && oct0[127]) {
    throw new Error(`Blocked SSRF ${label}: scan target '${rawToken}' covers loopback range 127.0.0.0/8`);
  }
  if (!allowPrivate) {
    if (
      oct0[10] ||
      (oct0[172] && anyIn(oct1, 16, 31)) ||
      (oct0[192] && oct1[168]) ||
      (oct0[100] && anyIn(oct1, 64, 127))
    ) {
      throw new Error(`Blocked SSRF ${label}: scan target '${rawToken}' covers private/CGNAT range`);
    }
  }
}

const IPV4_FORBIDDEN_CIDRS = [
  { cidr: '169.254.0.0/16', start: 0xa9fe0000, end: 0xa9feffff, kind: 'metadata' },
  { cidr: '0.0.0.0/8', start: 0x00000000, end: 0x00ffffff, kind: 'unspecified' },
  { cidr: '198.18.0.0/15', start: 0xc6120000, end: 0xc613ffff, kind: 'reserved' },
  { cidr: '192.88.99.0/24', start: 0xc0586300, end: 0xc05863ff, kind: 'reserved' },
  { cidr: '192.0.0.0/16', start: 0xc0000000, end: 0xc000ffff, kind: 'reserved' },
  { cidr: '224.0.0.0/4', start: 0xe0000000, end: 0xffffffff, kind: 'reserved' },
  { cidr: '127.0.0.0/8', start: 0x7f000000, end: 0x7fffffff, kind: 'loopback' },
  { cidr: '10.0.0.0/8', start: 0x0a000000, end: 0x0affffff, kind: 'private' },
  { cidr: '172.16.0.0/12', start: 0xac100000, end: 0xac1fffff, kind: 'private' },
  { cidr: '192.168.0.0/16', start: 0xc0a80000, end: 0xc0a8ffff, kind: 'private' },
  { cidr: '100.64.0.0/10', start: 0x64400000, end: 0x647fffff, kind: 'private' }
];

const IPV6_FORBIDDEN_CIDRS = [
  { cidr: 'fe80::/10', ...(() => { const [start, end] = ipv6CidrBounds(parseIpv6BigInt('fe80::'), 10); return { start, end }; })(), kind: 'metadata' },
  { cidr: 'fd00:ec2::254/128', ...(() => { const [start, end] = ipv6CidrBounds(parseIpv6BigInt('fd00:ec2::254'), 128); return { start, end }; })(), kind: 'metadata' },
  { cidr: '::ffff:169.254.0.0/112', ...(() => { const [start, end] = ipv6CidrBounds(parseIpv6BigInt('::ffff:169.254.0.0'), 112); return { start, end }; })(), kind: 'metadata' },
  { cidr: '::ffff:0:169.254.0.0/112', ...(() => { const [start, end] = ipv6CidrBounds(parseIpv6BigInt('::ffff:0:169.254.0.0'), 112); return { start, end }; })(), kind: 'metadata' },
  { cidr: '64:ff9b::169.254.0.0/112', ...(() => { const [start, end] = ipv6CidrBounds(parseIpv6BigInt('64:ff9b::169.254.0.0'), 112); return { start, end }; })(), kind: 'metadata' },
  { cidr: '2002:a9fe::/32', ...(() => { const [start, end] = ipv6CidrBounds(parseIpv6BigInt('2002:a9fe::'), 32); return { start, end }; })(), kind: 'metadata' },
  { cidr: '64:ff9b:1::/48', ...(() => { const [start, end] = ipv6CidrBounds(parseIpv6BigInt('64:ff9b:1::'), 48); return { start, end }; })(), kind: 'reserved' },
  { cidr: '2002::/16', ...(() => { const [start, end] = ipv6CidrBounds(parseIpv6BigInt('2002::'), 16); return { start, end }; })(), kind: 'reserved' },
  { cidr: '2001::/32', ...(() => { const [start, end] = ipv6CidrBounds(parseIpv6BigInt('2001::'), 32); return { start, end }; })(), kind: 'reserved' },
  { cidr: '::ffff:0:0:0/96', ...(() => { const [start, end] = ipv6CidrBounds(parseIpv6BigInt('::ffff:0:0:0'), 96); return { start, end }; })(), kind: 'reserved' },
  { cidr: 'fec0::/10', ...(() => { const [start, end] = ipv6CidrBounds(parseIpv6BigInt('fec0::'), 10); return { start, end }; })(), kind: 'reserved' },
  { cidr: '100::/64', ...(() => { const [start, end] = ipv6CidrBounds(parseIpv6BigInt('100::'), 64); return { start, end }; })(), kind: 'reserved' },
  { cidr: '2001:db8::/32', ...(() => { const [start, end] = ipv6CidrBounds(parseIpv6BigInt('2001:db8::'), 32); return { start, end }; })(), kind: 'reserved' },
  { cidr: 'ff00::/8', ...(() => { const [start, end] = ipv6CidrBounds(parseIpv6BigInt('ff00::'), 8); return { start, end }; })(), kind: 'reserved' },
  { cidr: '::/128', start: 0n, end: 0n, kind: 'unspecified' },
  { cidr: '::1/128', start: 1n, end: 1n, kind: 'loopback' },
  { cidr: 'fc00::/7', ...(() => { const [start, end] = ipv6CidrBounds(parseIpv6BigInt('fc00::'), 7); return { start, end }; })(), kind: 'private' }
];

/**
 * Scanner-aware SSRF & metadata/link-local guard supporting hostnames (with DNS resolution),
 * single IPv4/IPv6 addresses, CIDRs (including supernets like 169.0.0.0/8), and Nmap octet
 * ranges/wildcards (like 169.254.*.*, 169.254.169.1-254).
 *
 * @param {string} targetRaw
 * @param {Object} [options={}]
 * @returns {Promise<{ target: string, hostname: string, isIp: boolean, isRange: boolean, addresses: string[] }>}
 */
export async function assertSafeScanTarget(targetRaw, options = {}) {
  const {
    label = 'scan target',
    allowPrivate = process.env.VIGILANTE_ALLOW_PRIVATE_TARGETS === '1',
    allowLoopback = false,
    allowMetadata = false,
    allowLinkLocalMulticast = false,
    failOnDnsError = true,
    dnsLookup = dns.lookup
  } = options;

  const raw = String(targetRaw ?? '').trim();
  if (!raw || raw.startsWith('-') || /[\s\u0000-\u001f\u007f]/.test(raw)) {
    throw new Error(`Invalid ${label} '${targetRaw}'`);
  }

  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw)) {
    const res = await assertSafeOutboundTarget(raw, {
      label,
      allowPrivate,
      allowLoopback,
      allowMetadata,
      failOnDnsError,
      dnsLookup
    });
    return { target: raw, hostname: res.hostname, isIp: res.isIp, isRange: false, addresses: res.addresses };
  }

  if (raw.includes(',') && !isSingleIpv4OctetPattern(raw)) {
    const parts = raw.split(',').map((s) => s.trim()).filter(Boolean);
    if (parts.length === 0) {
      throw new Error(`Invalid ${label} '${targetRaw}'`);
    }
    const allAddresses = [];
    let firstRes = null;
    for (const part of parts) {
      const sub = await assertSafeScanTarget(part, options);
      if (!firstRes) firstRes = sub;
      allAddresses.push(...sub.addresses);
    }
    return {
      target: raw,
      hostname: firstRes.hostname,
      isIp: false,
      isRange: true,
      addresses: allAddresses
    };
  }

  if (allowLinkLocalMulticast && /^ff02::1(?:%[a-zA-Z0-9._-]+)?$/i.test(raw)) {
    return {
      target: raw,
      hostname: raw.toLowerCase(),
      isIp: true,
      isRange: false,
      addresses: ['ff02::1']
    };
  }

  // CIDR check (IPv4 or IPv6)
  if (raw.includes('/')) {
    const slashParts = raw.split('/');
    if (slashParts.length !== 2 || !/^\d{1,3}$/.test(slashParts[1])) {
      throw new Error(`Invalid ${label} CIDR '${targetRaw}'`);
    }
    const ipPart = slashParts[0].replace(/^\[|\]$/g, '').split('%')[0];
    const prefix = Number(slashParts[1]);
    const family = net.isIP(ipPart);
    if (family === 4) {
      if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
        throw new Error(`Invalid ${label} IPv4 CIDR '${targetRaw}'`);
      }
      const v4Int = parseIpv4Int(ipPart);
      const [netStart, netEnd] = ipv4CidrBounds(v4Int, prefix);
      for (const rule of IPV4_FORBIDDEN_CIDRS) {
        if (rule.kind === 'metadata' && allowMetadata) continue;
        if (rule.kind === 'loopback' && allowLoopback) continue;
        if (rule.kind === 'private' && allowPrivate) continue;
        if (ipv4RangesOverlap(netStart, netEnd, rule.start, rule.end)) {
          throw new Error(`Blocked SSRF ${label}: CIDR '${raw}' overlaps forbidden ${rule.kind} range ${rule.cidr}`);
        }
      }
      return { target: raw, hostname: ipPart, isIp: false, isRange: true, addresses: [] };
    }
    if (family === 6) {
      if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) {
        throw new Error(`Invalid ${label} IPv6 CIDR '${targetRaw}'`);
      }
      const v6Int = parseIpv6BigInt(ipPart);
      const [netStart, netEnd] = ipv6CidrBounds(v6Int, prefix);
      for (const rule of IPV6_FORBIDDEN_CIDRS) {
        if (rule.kind === 'metadata' && allowMetadata) continue;
        if (rule.kind === 'loopback' && allowLoopback) continue;
        if (rule.kind === 'private' && allowPrivate) continue;
        if (ipv6RangesOverlap(netStart, netEnd, rule.start, rule.end)) {
          throw new Error(`Blocked SSRF ${label}: CIDR '${raw}' overlaps forbidden ${rule.kind} range ${rule.cidr}`);
        }
      }
      return { target: raw, hostname: ipPart.toLowerCase(), isIp: false, isRange: true, addresses: [] };
    }
    throw new Error(`Invalid ${label} CIDR '${targetRaw}'`);
  }

  // Nmap IPv4 octet range / wildcard check (e.g. 169.254.*.*, 169.254.169.1-254)
  if (isSingleIpv4OctetPattern(raw) && net.isIP(raw) === 0) {
    const octets = raw.split('.').map(parseIpv4OctetValues);
    if (octets.some((o) => o === null)) {
      throw new Error(`Invalid ${label} IPv4 range '${targetRaw}'`);
    }
    assertIpv4ScanBoundsAllowed(octets[0], octets[1], octets[2], raw, { allowPrivate, allowLoopback, allowMetadata }, label);
    return { target: raw, hostname: raw, isIp: false, isRange: true, addresses: [] };
  }

  // Reject truncated wildcards or IPv6 wildcard/range syntax
  if (raw.includes('*') || (raw.includes(':') && net.isIP(raw.replace(/^\[|\]$/g, '').split('%')[0]) === 0 && !/^\[?[^\]]+\]?:\d+$/.test(raw))) {
    throw new Error(`Blocked SSRF ${label}: unsupported or unsafe wildcard/range target '${targetRaw}'`);
  }

  const out = await assertSafeOutboundTarget(raw, {
    label,
    allowBareHost: true,
    allowPrivate,
    allowLoopback,
    allowMetadata,
    failOnDnsError,
    dnsLookup
  });
  return {
    target: raw,
    hostname: out.hostname,
    isIp: out.isIp,
    isRange: false,
    addresses: out.addresses
  };
}
