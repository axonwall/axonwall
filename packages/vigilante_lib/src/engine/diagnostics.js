import net from 'node:net';
import { execa } from 'execa';
import { saveTriageBundle } from './evidence.js';
import { logger } from '../utils/logger.js';
import { assertCliTarget, isValidHostname } from './config.js';
import { assertSafeOutboundTarget } from './ssrf.js';

function assertDiagnosticHost(host, label) {
  const trimmed = (host || '127.0.0.1').trim();
  const clean = assertCliTarget(trimmed, label);
  const bare = clean.replace(/^\[|\]$/g, '');
  if (/[/?#@\s\u0000-\u001f\\]/.test(clean) || (!net.isIP(bare) && !isValidHostname(bare))) {
    throw new Error(`Invalid ${label} '${host}': must be a valid hostname or IP address`);
  }
  return bare;
}

function assertSafeHttpPath(httpPath = '/') {
  const cleanPath = String(httpPath ?? '/').trim() || '/';
  if (!cleanPath.startsWith('/') || /[\s\u0000-\u001f]/.test(cleanPath)) {
    throw new Error(`Invalid HTTP probe path '${httpPath}'`);
  }
  return cleanPath;
}

async function assertSafeDiagnosticTarget(targetOrUrl, label, options = {}, allowBareHost = true) {
  return assertSafeOutboundTarget(targetOrUrl, {
    label,
    allowBareHost,
    allowPrivate: options.allowPrivate,
    allowLoopback: options.allowLoopback,
    allowMetadata: false
  });
}

function formatHostAuthority(host) {
  return net.isIP(host) === 6 ? `[${host}]` : host;
}

function assertDiagnosticPort(port, defaultPort) {
  if (port === null || port === undefined || port === '') return defaultPort;
  const num = Number(port);
  if (!Number.isInteger(num) || num < 1 || num > 65535) {
    throw new Error(`Invalid port '${port}': expected integer between 1 and 65535`);
  }
  return num;
}

function assertBoundedCount(val, fallback, min, max, label) {
  const num = val === undefined || val === null ? fallback : Number(val);
  if (!Number.isInteger(num) || num < min || num > max) {
    throw new Error(`Invalid ${label} '${val}': expected integer between ${min} and ${max}`);
  }
  return num;
}

/**
 * Check if a command binary is available in PATH
 * @param {string} binary
 * @returns {Promise<boolean>}
 */
export async function isBinaryAvailable(binary) {
  try {
    await execa('which', [binary]);
    return true;
  } catch {
    return false;
  }
}

/**
 * Execute ICMP Ping against a host
 * @param {string} host
 * @param {number} [count=4]
 * @returns {Promise<{ success: boolean, output: string, error?: string }>}
 */
export async function runPing(host, count = 4, options = {}) {
  const target = assertDiagnosticHost(host, 'ping target');
  await assertSafeDiagnosticTarget(target, 'ping target', options);
  const cleanCount = assertBoundedCount(count, 4, 1, 20, 'ping count');
  logger.info('DIAG:PING', `Executing ping -c ${cleanCount} ${target}`);

  try {
    const { stdout, stderr } = await execa('ping', ['-c', String(cleanCount), '-W', '2', target]);
    return {
      success: true,
      command: `ping -c ${cleanCount} ${target}`,
      output: stdout || stderr
    };
  } catch (err) {
    logger.warn('DIAG:PING:ERROR', err.message);
    return {
      success: false,
      command: `ping -c ${cleanCount} ${target}`,
      output: err.stdout || err.message,
      error: err.message
    };
  }
}

/**
 * Execute HTTP Benchmark using ApacheBench (ab) or curl fallback
 * @param {string} host
 * @param {Object} [options]
 * @param {number} [options.port]
 * @param {boolean} [options.isHttps=false]
 * @param {string} [options.path='/']
 * @param {number} [options.requests=50]
 * @param {number} [options.concurrency=5]
 * @returns {Promise<{ success: boolean, output: string, tool: string }>}
 */
export async function runBenchmark(host, {
  port = null,
  isHttps = false,
  path = '/',
  requests = 50,
  concurrency = 5,
  allowPrivate,
  allowLoopback
} = {}) {
  const target = assertDiagnosticHost(host, 'benchmark target');
  const portNum = assertDiagnosticPort(port, isHttps ? 443 : 80);
  const protocol = isHttps || portNum === 443 ? 'https' : 'http';
  const cleanPath = assertSafeHttpPath(path);
  const targetUrl = `${protocol}://${formatHostAuthority(target)}:${portNum}${cleanPath}`;
  await assertSafeDiagnosticTarget(targetUrl, 'benchmark target', { allowPrivate, allowLoopback }, false);
  const cleanRequests = assertBoundedCount(requests, 50, 1, 500, 'benchmark requests');
  const cleanConcurrency = assertBoundedCount(concurrency, 5, 1, 50, 'benchmark concurrency');

  const hasAb = await isBinaryAvailable('ab');

  if (hasAb) {
    logger.info('DIAG:AB', `Executing ab -n ${cleanRequests} -c ${cleanConcurrency} ${targetUrl}`);
    try {
      const { stdout } = await execa('ab', ['-n', String(cleanRequests), '-c', String(cleanConcurrency), '-k', targetUrl]);
      return {
        success: true,
        tool: 'ab (ApacheBench)',
        command: `ab -n ${cleanRequests} -c ${cleanConcurrency} -k ${targetUrl}`,
        output: stdout
      };
    } catch (err) {
      return {
        success: false,
        tool: 'ab (ApacheBench)',
        command: `ab -n ${cleanRequests} -c ${cleanConcurrency} -k ${targetUrl}`,
        output: err.stdout || err.message,
        error: err.message
      };
    }
  }

  // Fallback to multiple parallel curl requests
  logger.info('DIAG:BENCH_CURL', `Executing curl benchmark loop against ${targetUrl}`);
  try {
    const startTime = Date.now();
    const probeCount = Math.min(cleanRequests, 10);
    const curlPromises = [];
    for (let i = 0; i < probeCount; i++) {
      curlPromises.push(execa('curl', [
        '-s',
        '--proto', '=http,https',
        '-o', '/dev/null',
        '-w', 'HTTP %{http_code} | Connect: %{time_connect}s | TTFB: %{time_starttransfer}s | Total: %{time_total}s\n',
        '--connect-timeout', '2',
        '--max-time', '5',
        targetUrl
      ]));
    }
    const results = await Promise.allSettled(curlPromises);
    const totalTimeMs = Date.now() - startTime;
    const lines = [
      `=== HTTP Benchmark Fallback (curl) for ${targetUrl} ===`,
      `Executed ${probeCount} concurrent HTTP probes in ${(totalTimeMs / 1000).toFixed(3)}s`,
      '',
      ...results.map((r, i) => r.status === 'fulfilled' ? `[Req #${i + 1}] ${r.value.stdout.trim()}` : `[Req #${i + 1}] Failed: ${r.reason.message}`),
      '',
      `Tip: Install 'apache2-utils' (or 'httpd-tools') for full ApacheBench (ab) metrics.`
    ];

    return {
      success: true,
      tool: 'curl benchmark fallback',
      command: `curl concurrent benchmark against ${targetUrl}`,
      output: lines.join('\n')
    };
  } catch (err) {
    return {
      success: false,
      tool: 'curl',
      command: `curl ${targetUrl}`,
      output: err.message,
      error: err.message
    };
  }
}

/**
 * Execute MTR (My Traceroute) or traceroute against host
 * @param {string} host
 * @param {Object} [options]
 * @returns {Promise<{ success: boolean, output: string, tool: string }>}
 */
export async function runMtr(host, options = {}) {
  const target = assertDiagnosticHost(host, 'mtr target');
  await assertSafeDiagnosticTarget(target, 'mtr target', options);
  const hasMtr = await isBinaryAvailable('mtr');

  if (hasMtr) {
    logger.info('DIAG:MTR', `Executing mtr --report -c 4 ${target}`);
    try {
      const { stdout } = await execa('mtr', ['--report', '-c', '4', target]);
      return {
        success: true,
        tool: 'mtr',
        command: `mtr --report -c 4 ${target}`,
        output: stdout
      };
    } catch (err) {
      return {
        success: false,
        tool: 'mtr',
        command: `mtr --report -c 4 ${target}`,
        output: err.stdout || err.message,
        error: err.message
      };
    }
  }

  // Fallback to traceroute or tracepath
  const hasTracepath = await isBinaryAvailable('tracepath');
  if (hasTracepath) {
    logger.info('DIAG:TRACEPATH', `Executing tracepath ${target}`);
    try {
      const { stdout } = await execa('tracepath', ['-m', '15', target]);
      return {
        success: true,
        tool: 'tracepath (mtr fallback)',
        command: `tracepath ${target}`,
        output: stdout
      };
    } catch (err) {
      return {
        success: false,
        tool: 'tracepath',
        command: `tracepath ${target}`,
        output: err.stdout || err.message,
        error: err.message
      };
    }
  }

  return {
    success: false,
    tool: 'mtr',
    command: `mtr ${target}`,
    output: `Neither 'mtr' nor 'tracepath' found in system PATH. Install via 'sudo apt install mtr' or 'brew install mtr'.`,
    error: 'mtr not installed'
  };
}

/**
 * Execute HTTP Header & TLS Inspector (curl -I)
 * @param {string} host
 * @param {Object} [options]
 * @returns {Promise<{ success: boolean, output: string }>}
 */
export async function runCurlHeaders(host, { port = null, isHttps = false, path = '/', allowPrivate, allowLoopback } = {}) {
  const target = assertDiagnosticHost(host, 'curl target');
  const portNum = assertDiagnosticPort(port, isHttps ? 443 : 80);
  const protocol = isHttps || portNum === 443 ? 'https' : 'http';
  const cleanPath = assertSafeHttpPath(path);
  const targetUrl = `${protocol}://${formatHostAuthority(target)}:${portNum}${cleanPath}`;
  await assertSafeDiagnosticTarget(targetUrl, 'curl target', { allowPrivate, allowLoopback }, false);

  logger.info('DIAG:CURL_HEADERS', `Executing curl -I -sS -k ${targetUrl}`);
  try {
    const { stdout, stderr } = await execa('curl', [
      '-I',
      '-sS',
      '-k',
      '--proto', '=http,https',
      '--connect-timeout', '3',
      '--max-time', '8',
      targetUrl
    ]);
    return {
      success: true,
      command: `curl -I -k ${targetUrl}`,
      output: stdout || stderr
    };
  } catch (err) {
    return {
      success: false,
      command: `curl -I -k ${targetUrl}`,
      output: err.stdout || err.message,
      error: err.message
    };
  }
}

/**
 * Execute DNS resolution & reverse lookup (dig / nslookup)
 * @param {string} host
 * @param {Object} [options]
 * @returns {Promise<{ success: boolean, output: string }>}
 */
export async function runDnsLookup(host, options = {}) {
  const target = assertDiagnosticHost(host, 'dig target');
  await assertSafeDiagnosticTarget(target, 'dig target', options);
  const hasDig = await isBinaryAvailable('dig');

  if (hasDig) {
    logger.info('DIAG:DIG', `Executing dig ${target}`);
    try {
      const isIp = net.isIP(target) !== 0;
      const digArgs = isIp ? ['-x', target, '+noall', '+answer', '+stats'] : [target, 'ANY', '+noall', '+answer', '+stats'];
      const { stdout } = await execa('dig', digArgs);
      return {
        success: true,
        tool: 'dig',
        command: `dig ${digArgs.join(' ')}`,
        output: stdout || 'No DNS records returned for target.'
      };
    } catch (err) {
      return {
        success: false,
        tool: 'dig',
        command: `dig ${target}`,
        output: err.stdout || err.message,
        error: err.message
      };
    }
  }

  return {
    success: false,
    tool: 'dig',
    command: `dig ${target}`,
    output: `dig utility not found. Install via 'sudo apt install dnsutils' or 'brew install bind'.`,
    error: 'dig not installed'
  };
}

/**
 * Extract full TLS certificate chain and crypto metadata using OpenSSL s_client
 * @param {string} host
 * @param {number} [port=443]
 * @param {Object} [options]
 * @returns {Promise<{ success: boolean, output: string, command: string }>}
 */
export async function runTlsCertDump(host, port = 443, options = {}) {
  const target = assertDiagnosticHost(host, 'tls target');
  await assertSafeDiagnosticTarget(target, 'tls target', options);
  const portNum = assertDiagnosticPort(port, 443);
  const connectTarget = `${formatHostAuthority(target)}:${portNum}`;
  logger.info('DIAG:TLS_CERTS', `Executing openssl s_client -showcerts -connect ${connectTarget}`);

  try {
    const args = ['s_client', '-showcerts', '-connect', connectTarget];
    if (!net.isIP(target)) {
      args.push('-servername', target);
    }
    const { stdout, stderr } = await execa('openssl', args, {
      input: 'Q\n',
      timeout: 5000
    });

    const cmdDisplay = net.isIP(target)
      ? `openssl s_client -showcerts -connect ${connectTarget}`
      : `openssl s_client -showcerts -connect ${connectTarget} -servername ${target}`;
    return {
      success: true,
      tool: 'OpenSSL TLS Certificate Chain',
      command: cmdDisplay,
      output: stdout || stderr
    };
  } catch (err) {
    return {
      success: false,
      tool: 'OpenSSL TLS Certificate Chain',
      command: `openssl s_client -showcerts -connect ${connectTarget}`,
      output: err.stdout || err.message,
      error: err.message
    };
  }
}

/**
 * Query kernel ARP cache and neighbor table for the host
 * @param {string} host
 * @returns {Promise<{ success: boolean, output: string, command: string, entries: Array<string> }>}
 */
export async function runArpNeighLookup(host) {
  const raw = String(host || '').trim();
  const target = raw ? assertDiagnosticHost(raw, 'arp target') : '';
  logger.info('DIAG:ARP_NEIGH', `Checking kernel neighbor table for ${target}`);

  try {
    const hasIp = await isBinaryAvailable('ip');
    let stdout = '';
    let command = '';

    if (hasIp) {
      command = 'ip neigh show';
      const res = await execa('ip', ['neigh', 'show']);
      stdout = res.stdout;
    } else {
      command = 'arp -a';
      const res = await execa('arp', ['-a']);
      stdout = res.stdout;
    }

    const lines = stdout.split('\n').filter(l => l.trim().length > 0);
    const hostMatches = target ? lines.filter(l => l.includes(target)) : lines;

    return {
      success: true,
      tool: 'Kernel ARP & Neighbor Table',
      command,
      output: hostMatches.length > 0
        ? `=== ARP / Neighbor Records for ${target} ===\n` + hostMatches.join('\n')
        : `No direct neighbor/ARP entry cached for ${target}.\n\nFull ARP Table:\n` + stdout,
      entries: hostMatches
    };
  } catch (err) {
    return {
      success: false,
      tool: 'ARP & Neighbor Table',
      command: 'ip neigh show',
      output: err.message,
      error: err.message,
      entries: []
    };
  }
}

/**
 * Run a full forensic Incident Response Triage Bundle for a host and persist to evidence vault
 * @param {string} host
 * @param {Object} [options]
 * @param {string} [options.networkCidr='local_net']
 * @param {number} [options.port]
 * @param {boolean} [options.isHttps=false]
 * @returns {Promise<{ success: boolean, bundle: Object, saved: Object, durationMs: number }>}
 */
export async function runFullTriageCapture(host, {
  networkCidr = 'local_network',
  port = null,
  ports = [],
  isHttps = false,
  allowPrivate,
  allowLoopback
} = {}) {
  const target = assertDiagnosticHost(host, 'triage target');
  const ssrfOpts = { allowPrivate, allowLoopback };
  await assertSafeDiagnosticTarget(target, 'triage target', ssrfOpts);
  const resolvedPort = port ?? (Array.isArray(ports) && ports.length > 0 ? ports[0] : null);
  if (resolvedPort !== null && resolvedPort !== undefined) {
    assertDiagnosticPort(resolvedPort, 443);
  }
  const startTime = Date.now();
  logger.info('DIAG:TRIAGE_ALL', `Running complete IR triage bundle on ${target} (${networkCidr})`);

  // Run all forensic probes concurrently
  const [pingRes, mtrRes, dnsRes, tlsRes, httpRes, arpRes, benchRes] = await Promise.allSettled([
    runPing(target, 4, ssrfOpts),
    runMtr(target, ssrfOpts),
    runDnsLookup(target, ssrfOpts),
    runTlsCertDump(target, resolvedPort || 443, ssrfOpts),
    runCurlHeaders(target, { port: resolvedPort, isHttps, ...ssrfOpts }),
    runArpNeighLookup(target),
    runBenchmark(target, { port: resolvedPort, isHttps, requests: 20, concurrency: 4, ...ssrfOpts })
  ]);

  const bundle = {
    metadata: {
      target,
      networkCidr,
      durationMs: Date.now() - startTime,
      collectedAt: new Date().toISOString()
    },
    ping: pingRes.status === 'fulfilled' ? pingRes.value : { error: pingRes.reason?.message },
    mtr: mtrRes.status === 'fulfilled' ? mtrRes.value : { error: mtrRes.reason?.message },
    dns: dnsRes.status === 'fulfilled' ? dnsRes.value : { error: dnsRes.reason?.message },
    tls: tlsRes.status === 'fulfilled' ? tlsRes.value : { error: tlsRes.reason?.message },
    http: httpRes.status === 'fulfilled' ? httpRes.value : { error: httpRes.reason?.message },
    arp: arpRes.status === 'fulfilled' ? arpRes.value : { error: arpRes.reason?.message },
    benchmark: benchRes.status === 'fulfilled' ? benchRes.value : { error: benchRes.reason?.message }
  };

  const saved = await saveTriageBundle(networkCidr, target, bundle);

  return {
    success: true,
    bundle,
    saved,
    durationMs: Date.now() - startTime
  };
}
