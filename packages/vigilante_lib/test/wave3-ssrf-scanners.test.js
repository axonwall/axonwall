import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

import {
  classifyIpRange,
  assertSafeOutboundTarget,
  assertSafeScanTarget,
  createPinnedLookup,
  readResponseWithLimit,
  safeFetch
} from '../src/engine/ssrf.js';
import { RECON_PROFILES, probePortsNative, probeHttpNative } from '../src/engine/recon.js';
import { checkZapAvailable, runZapScan } from '../src/engine/zap.js';
import { probeServiceSla, AttackDefenseRunner, generateAdTickFlag } from '../src/engine/ad-runner.js';
import { runCurlHeaders, runBenchmark } from '../src/engine/diagnostics.js';
import { NUCLEI_PROFILES } from '../src/engine/nuclei.js';
import { syncFeodoTrackerC2 } from '../src/engine/cti.js';
import { checkBloodhoundAvailable } from '../src/engine/bloodhound.js';
import {
  runOobScan,
  sanitizeOobCustomArgs,
  parseOobReportContent
} from '../src/engine/oobscan.js';
import { runNmapScan } from '../src/engine/nmap.js';
import { runNetexecAudit, probeAuthProtocolsNative, NETEXEC_PROFILES } from '../src/engine/netexec.js';
import { runKubeAudit, KUBEAUDIT_PROFILES } from '../src/engine/kubeaudit.js';
import {
  runHostVulnerabilityScan,
  getOpenVasCredentials,
  checkOpenVasStatus,
  gvmCliCommand,
  buildGvmConfigIni
} from '../src/engine/openvas.js';
import {
  runTrivyAudit,
  parseTrivyOutput,
  buildTrivyDockerArgs,
  TRIVY_IMAGE,
  TRIVY_PROFILES
} from '../src/engine/trivy.js';
import { openInSystemPager } from '../src/engine/pods.js';
import { resolveChartValuesArgs, cleanupHelmTempValues } from '../src/engine/helm.js';
import {
  testChallengeConnection,
  generateEphemeralSandboxManifest,
  spawnEphemeralSandbox,
  sanitizeSafeTeamId
} from '../src/engine/kctf.js';
import { TournamentEngine } from '../src/engine/tournament.js';
import { getVigilanteConfigDir } from '../src/engine/config.js';

let tempRoot;
let prevConfigDir;
let prevXdgHome;
let prevAllowPriv;
let prevCtfSecret;

before(async () => {
  tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-w3-test-'));
  prevConfigDir = process.env.VIGILANTE_CONFIG_DIR;
  prevXdgHome = process.env.XDG_CONFIG_HOME;
  prevAllowPriv = process.env.VIGILANTE_ALLOW_PRIVATE_TARGETS;
  prevCtfSecret = process.env.VIGILANTE_CTF_SECRET;

  process.env.VIGILANTE_CONFIG_DIR = path.join(tempRoot, 'cfg');
  process.env.XDG_CONFIG_HOME = tempRoot;
  delete process.env.VIGILANTE_ALLOW_PRIVATE_TARGETS;
  process.env.VIGILANTE_CTF_SECRET = 'wave3-test-ctf-secret-0123456789';
});

after(async () => {
  if (prevConfigDir === undefined) delete process.env.VIGILANTE_CONFIG_DIR;
  else process.env.VIGILANTE_CONFIG_DIR = prevConfigDir;
  if (prevXdgHome === undefined) delete process.env.XDG_CONFIG_HOME;
  else process.env.XDG_CONFIG_HOME = prevXdgHome;
  if (prevAllowPriv === undefined) delete process.env.VIGILANTE_ALLOW_PRIVATE_TARGETS;
  else process.env.VIGILANTE_ALLOW_PRIVATE_TARGETS = prevAllowPriv;
  if (prevCtfSecret === undefined) delete process.env.VIGILANTE_CTF_SECRET;
  else process.env.VIGILANTE_CTF_SECRET = prevCtfSecret;

  await fs.rm(tempRoot, { recursive: true, force: true });
});

async function listenHttp(handler) {
  const srv = http.createServer(handler);
  await new Promise((resolve) => srv.listen(0, '127.0.0.1', resolve));
  return {
    server: srv,
    port: srv.address().port,
    close: () => new Promise((resolve) => {
      srv.closeAllConnections?.();
      srv.close(resolve);
    })
  };
}

async function withFakeBin(binName, scriptContent, fn) {
  const binDir = await fs.mkdtemp(path.join(tempRoot, 'fakebin-'));
  const binPath = path.join(binDir, binName);
  await fs.writeFile(binPath, scriptContent, { encoding: 'utf8', mode: 0o755 });
  const prevPath = process.env.PATH || '';
  process.env.PATH = `${binDir}:${prevPath}`;
  try {
    return await fn(binDir, binPath);
  } finally {
    process.env.PATH = prevPath;
    await fs.rm(binDir, { recursive: true, force: true });
  }
}

describe('SEC-H34: IPv6 transition/special-use classification & fail-closed DNS default', () => {
  it('blocks IPv6 transition, deprecated, and special-use IPv4/IPv6 ranges and unwraps embedded IPv4', async () => {
    assert.equal(classifyIpRange('64:ff9b:1::1'), 'reserved');
    assert.equal(classifyIpRange('64:ff9b:1::169.254.169.254'), 'metadata');
    assert.equal(classifyIpRange('2002:a9fe:a9fe::1'), 'metadata');
    assert.equal(classifyIpRange('2002:7f00:1::1'), 'reserved');
    assert.equal(classifyIpRange('2002:0808:0808::1'), 'reserved');
    assert.equal(classifyIpRange('2001:0:4136:e378::1'), 'reserved');
    assert.equal(classifyIpRange('::ffff:0:169.254.169.254'), 'metadata');
    assert.equal(classifyIpRange('::ffff:0:a9fe:a9fe'), 'metadata');
    assert.equal(classifyIpRange('::ffff:0:127.0.0.1'), 'reserved');
    assert.equal(classifyIpRange('::ffff:0:8.8.8.8'), 'reserved');
    assert.equal(classifyIpRange('fec0::1'), 'reserved');
    assert.equal(classifyIpRange('100::1'), 'reserved');
    assert.equal(classifyIpRange('2001:db8::1'), 'reserved');
    assert.equal(classifyIpRange('198.18.0.1'), 'reserved');
    assert.equal(classifyIpRange('198.19.255.254'), 'reserved');
    assert.equal(classifyIpRange('192.88.99.1'), 'reserved');

    // All of them remain blocked even with allowPrivate + allowLoopback
    for (const ip of [
      '[64:ff9b:1::1]',
      '[2002:a9fe:a9fe::1]',
      '[2002:0808:0808::1]',
      '[2001:0:4136:e378::1]',
      '[::ffff:0:a9fe:a9fe]',
      '[::ffff:0:8.8.8.8]',
      '[fec0::1]',
      '[100::1]',
      '[2001:db8::1]',
      '198.18.0.1',
      '192.88.99.1'
    ]) {
      await assert.rejects(
        assertSafeOutboundTarget(`http://${ip}/`, { allowPrivate: true, allowLoopback: true }),
        /Blocked SSRF/,
        `Expected ${ip} to be blocked`
      );
    }
  });

  it('defaults failOnDnsError to true in assertSafeOutboundTarget while preserving opt-out', async () => {
    await assert.rejects(
      assertSafeOutboundTarget('https://nonexistent.invalid/api', {
        dnsLookup: async () => { throw new Error('ENOTFOUND'); }
      }),
      /DNS resolution failed/
    );
    await assert.rejects(
      assertSafeOutboundTarget('https://empty.invalid/api', {
        dnsLookup: async () => []
      }),
      /DNS resolution returned no addresses/
    );

    const optOut = await assertSafeOutboundTarget('https://nonexistent.invalid/api', {
      failOnDnsError: false,
      dnsLookup: async () => { throw new Error('ENOTFOUND'); }
    });
    assert.deepEqual(optOut.addresses, []);
  });
});

describe('SEC-H35 & SEC-M40: DNS pinning, redirect blocking, and response size caps', () => {
  it('createPinnedLookup returns pinned addresses and safeFetch pins DNS, blocks redirects, and caps oversized streams', async () => {
    const pinnedLookup = createPinnedLookup(['127.0.0.1', '2606:4700:4700::1111']);
    const single = await new Promise((resolve, reject) => {
      pinnedLookup('rebind.invalid', {}, (err, addr, fam) => (err ? reject(err) : resolve({ addr, fam })));
    });
    assert.deepEqual(single, { addr: '127.0.0.1', fam: 4 });

    const allRecs = await new Promise((resolve, reject) => {
      pinnedLookup('rebind.invalid', { all: true }, (err, recs) => (err ? reject(err) : resolve(recs)));
    });
    assert.equal(allRecs.length, 2);
    assert.equal(allRecs[1].family, 6);

    let dnsCalls = 0;
    let redirectTargetHits = 0;
    const targetSrv = await listenHttp((req, res) => {
      if (req.url === '/ok') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ host: req.headers.host, ok: true }));
      } else if (req.url === '/redir') {
        res.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data/' });
        res.end();
      } else if (req.url === '/big-chunked') {
        res.writeHead(200, { 'content-type': 'text/plain' });
        res.write('A'.repeat(1024));
        res.write('B'.repeat(1024));
        res.end();
      } else if (req.url === '/big-cl') {
        res.writeHead(200, { 'content-type': 'text/plain', 'content-length': '50000' });
        res.end('x'.repeat(50000));
      } else if (req.url === '/secret-hop') {
        redirectTargetHits++;
        res.writeHead(200);
        res.end('should-not-reach');
      }
    });

    try {
      // TOCTOU rebind mock: call 1 returns 127.0.0.1, call 2 would return metadata if re-queried!
      const rebindDns = async () => {
        dnsCalls++;
        if (dnsCalls === 1) return [{ address: '127.0.0.1', family: 4 }];
        return [{ address: '169.254.169.254', family: 4 }];
      };

      const okRes = await safeFetch(
        `http://rebind.invalid:${targetSrv.port}/ok`,
        {},
        { allowLoopback: true, dnsLookup: rebindDns }
      );
      const okJson = JSON.parse(await readResponseWithLimit(okRes, 4096));
      assert.equal(okJson.ok, true);
      assert.equal(okJson.host, `rebind.invalid:${targetSrv.port}`);
      assert.equal(dnsCalls, 1);

      // Redirect blocked by default (redirect: 'error')
      await assert.rejects(
        safeFetch(`http://127.0.0.1:${targetSrv.port}/redir`, {}, { allowLoopback: true }),
        /redirect/i
      );

      // Redirect with follow re-validates hop and blocks metadata redirect target
      await assert.rejects(
        safeFetch(`http://127.0.0.1:${targetSrv.port}/redir`, { redirect: 'follow' }, { allowLoopback: true }),
        /Blocked SSRF/
      );
      assert.equal(redirectTargetHits, 0);

      // Oversized chunked response aborted by readResponseWithLimit
      const chunkedRes = await safeFetch(`http://127.0.0.1:${targetSrv.port}/big-chunked`, {}, { allowLoopback: true });
      await assert.rejects(
        readResponseWithLimit(chunkedRes, 512),
        /exceeded maximum allowed size/
      );

      // Oversized Content-Length rejected eagerly
      await assert.rejects(
        safeFetch(`http://127.0.0.1:${targetSrv.port}/big-cl`, {}, { allowLoopback: true, maxBytes: 512 }),
        /exceeded maximum allowed size/
      );
    } finally {
      await targetSrv.close();
    }
  });

  it('wires pinned DNS, redirect blocking, and size limits into recon, zap, ad-runner, diagnostics, nuclei, cti, bloodhound', async () => {
    const srv = await listenHttp((req, res) => {
      if (req.url === '/JSON/core/view/version/') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ version: '2.15.0' }));
      } else if (req.url === '/api/v2/health') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      } else if (req.url === '/redir') {
        res.writeHead(302, { Location: 'http://169.254.169.254/latest' });
        res.end();
      } else if (req.url === '/big') {
        res.writeHead(200, { 'content-type': 'text/html' });
        res.end('<html><title>' + 'X'.repeat(4096) + '</title></html>');
      } else {
        res.writeHead(200, { 'content-type': 'text/html', server: 'VigilanteMock' });
        res.end('<html><title>Pinned</title></html>');
      }
    });

    try {
      // recon.js: httpx -fr=false flag, probeHttpNative pinned + size cap, probePortsNative pinned
      const httpxProfile = RECON_PROFILES.find((p) => p.id === 'web-probe');
      const httpxArgs = httpxProfile.buildArgs('https://example.com');
      assert.ok(httpxArgs.includes('-fr=false'), 'httpx args must disable redirects via -fr=false');

      const reconOk = await probeHttpNative(`http://rebind.invalid:${srv.port}/`, {
        allowLoopback: true,
        dnsLookup: async () => [{ address: '127.0.0.1', family: 4 }]
      });
      assert.equal(reconOk.failed, false);
      assert.equal(reconOk.title, 'Pinned');

      const reconBig = await probeHttpNative(`http://127.0.0.1:${srv.port}/big`, {
        allowLoopback: true,
        maxBytes: 256
      });
      assert.equal(reconBig.failed, true);
      assert.match(reconBig.error, /exceeded maximum allowed size/);

      const reconPorts = await probePortsNative('pinned-tcp.invalid', [srv.port], 800, {
        allowLoopback: true,
        dnsLookup: async () => [{ address: '127.0.0.1', family: 4 }]
      });
      assert.equal(reconPorts.length, 1);
      assert.equal(reconPorts[0].port, srv.port);

      // zap.js: pinned ZAP API check and fail-closed on explicit unresolvable zapBaseUrl
      const zapOk = await checkZapAvailable(`http://zap-pinned.invalid:${srv.port}`, '', {
        dnsLookup: async () => [{ address: '127.0.0.1', family: 4 }]
      });
      assert.equal(zapOk.reachable, true);
      assert.equal(zapOk.version, '2.15.0');

      await assert.rejects(
        runZapScan(`http://127.0.0.1:${srv.port}`, 'quick', {
          allowLoopback: true,
          zapBaseUrl: 'http://bad-explicit-zap.invalid',
          dnsLookup: async (h) => {
            if (h === 'bad-explicit-zap.invalid') throw new Error('ENOTFOUND');
            return [{ address: '127.0.0.1', family: 4 }];
          }
        }),
        /DNS resolution failed/
      );

      // ad-runner.js: pinned HTTP + TCP SLA probes and redirect rejection
      const adHttp = await probeServiceSla({
        host: 'ad-team.invalid',
        port: srv.port,
        serviceType: 'HTTP',
        path: '/',
        allowLoopback: true,
        dnsLookup: async () => [{ address: '127.0.0.1', family: 4 }]
      });
      assert.equal(adHttp.status, 'UP');

      const adRedir = await probeServiceSla({
        host: '127.0.0.1',
        port: srv.port,
        serviceType: 'HTTP',
        path: '/redir',
        allowLoopback: true
      });
      assert.equal(adRedir.status, 'DOWN');

      const adTcp = await probeServiceSla({
        host: 'ad-team.invalid',
        port: srv.port,
        serviceType: 'TCP',
        allowLoopback: true,
        dnsLookup: async () => [{ address: '127.0.0.1', family: 4 }]
      });
      assert.equal(adTcp.status, 'UP');

      // diagnostics.js: curl uses --resolve host:port:pinnedIp and --max-redirs 0 (real curl + argv verification)
      const curlRes = await runCurlHeaders('curl-pinned.invalid', {
        port: srv.port,
        allowLoopback: true,
        dnsLookup: async () => [{ address: '127.0.0.1', family: 4 }]
      });
      assert.equal(curlRes.success, true);
      assert.match(curlRes.output, /HTTP\/1\.1 200 OK/);
      assert.match(curlRes.command, /--max-redirs 0/);

      const curlRedirRes = await runCurlHeaders('curl-redir.invalid', {
        port: srv.port,
        path: '/redir',
        allowLoopback: true,
        dnsLookup: async () => [{ address: '127.0.0.1', family: 4 }]
      });
      assert.doesNotMatch(curlRedirRes.output, /HTTP\/1\.1 200/);

      const curlArgvFile = path.join(tempRoot, 'curl-argv.json');
      await withFakeBin(
        'curl',
        `#!/usr/bin/env node
const fs = require('node:fs');
fs.writeFileSync(${JSON.stringify(curlArgvFile)}, JSON.stringify(process.argv.slice(2)));
console.log('HTTP/1.1 200 OK');
`,
        async () => {
          await runCurlHeaders('curl-shim.invalid', {
            port: 8443,
            isHttps: true,
            allowLoopback: true,
            dnsLookup: async () => [{ address: '127.0.0.1', family: 4 }]
          });
          const curlArgv = JSON.parse(await fs.readFile(curlArgvFile, 'utf8'));
          assert.ok(curlArgv.includes('--max-redirs') && curlArgv[curlArgv.indexOf('--max-redirs') + 1] === '0');
          assert.ok(!curlArgv.includes('-L') && !curlArgv.includes('--location'));
          assert.ok(curlArgv.includes('--resolve'));
          assert.equal(curlArgv[curlArgv.indexOf('--resolve') + 1], 'curl-shim.invalid:8443:127.0.0.1');
        }
      );

      const benchRes = await runBenchmark('bench-pinned.invalid', {
        port: srv.port,
        requests: 2,
        concurrency: 1,
        allowLoopback: true,
        dnsLookup: async () => [{ address: '127.0.0.1', family: 4 }]
      });
      assert.equal(benchRes.success, true);

      // nuclei.js: -dr on all profiles
      for (const prof of NUCLEI_PROFILES) {
        const args = prof.buildArgs('https://example.com');
        assert.ok(args.includes('-dr'), `Nuclei profile '${prof.id}' must include -dr`);
      }

      // cti.js: syncFeodoTrackerC2 enforces safeFetch/limit gracefully
      const ctiRes = await syncFeodoTrackerC2({ forceRefresh: true, maxBytes: 128 });
      assert.ok(Array.isArray(ctiRes.ips) && ctiRes.ips.length > 0);

      // bloodhound.js: blocks metadata/private/loopback SSRF and blocks redirects
      await assert.rejects(
        checkBloodhoundAvailable({ url: 'http://169.254.169.254/latest/meta-data/' }),
        /Blocked SSRF/
      );
      await assert.rejects(
        checkBloodhoundAvailable({ url: 'http://10.0.0.1:8080/api/v2/health' }),
        /Blocked SSRF/
      );
      const bhRedir = await checkBloodhoundAvailable({
        url: `http://127.0.0.1:${srv.port}/redir`,
        allowLoopback: true
      });
      assert.equal(bhRedir.reachable, false);
      assert.match(bhRedir.error, /redirect/i);

      const bhOk = await checkBloodhoundAvailable({
        url: `http://bh-pinned.invalid:${srv.port}/api/v2/health`,
        allowLoopback: true,
        dnsLookup: async () => [{ address: '127.0.0.1', family: 4 }]
      });
      assert.equal(bhOk.reachable, true);
    } finally {
      await srv.close();
    }
  });
});

describe('SEC-H36: Scanner SSRF & metadata/link-local guards', () => {
  it('oobscan.js blocks target/file override flags in customArgs and blocks SSRF/metadata/DNS-rebind targets', async () => {
    for (const badArgs of [
      ['-t', '169.254.169.254'],
      ['-targets', '169.254.169.254'],
      ['-targets=169.254.169.254'],
      ['--targets', '10.0.0.1'],
      ['-list', '/etc/passwd'],
      ['-l', 'targets.txt'],
      ['-o', '/tmp/evil'],
      ['-f', '/etc/passwd']
    ]) {
      assert.throws(() => sanitizeOobCustomArgs(badArgs), /Disallowed|Unsupported/);
      await assert.rejects(
        runOobScan({ target: '10.0.100.5', profile: 'custom', customArgs: badArgs }),
        /Disallowed|Unsupported/
      );
    }

    for (const badTarget of [
      '169.254.169.254',
      '169.254.0.0/16',
      '169.0.0.0/8',
      'metadata.google.internal',
      'fe80::1',
      'fd00:ec2::254',
      '::ffff:169.254.169.254',
      '2002:a9fe:a9fe::1'
    ]) {
      await assert.rejects(runOobScan({ target: badTarget }), /Blocked SSRF/);
    }

    await assert.rejects(
      runOobScan({
        target: 'bmc-rebind.invalid',
        dnsLookup: async () => [{ address: '169.254.169.254', family: 4 }]
      }),
      /Blocked SSRF/
    );
  });

  it('nmap.js assertSafeScanTarget & runNmapScan block metadata CIDRs, supernets, wildcards, ranges, and DNS rebinding', async () => {
    for (const badTarget of [
      '169.254.169.254',
      '169.254.0.0/16',
      '169.0.0.0/8',
      '0.0.0.0/0',
      '128.0.0.0/1',
      '169.254.*.*',
      '169.254.169.1-254',
      '168-170.254.0.1',
      '169.254.1,2.3',
      '169.254.*',
      '10.0.0.1,169.254.169.254',
      'fe80::/10',
      'fe80::1',
      'fd00:ec2::254/128',
      'fd00:ec2::254',
      'fd00::/8',
      '64:ff9b:1::/48',
      '2002::/16',
      '198.18.0.0/15',
      '192.88.99.0/24',
      'metadata.google.internal'
    ]) {
      await assert.rejects(
        assertSafeScanTarget(badTarget, { allowPrivate: true, allowLoopback: true }),
        /Blocked SSRF/,
        `assertSafeScanTarget should block '${badTarget}'`
      );
      await assert.rejects(
        runNmapScan({ target: badTarget }),
        /Blocked SSRF/,
        `runNmapScan should block '${badTarget}'`
      );
    }

    await assert.rejects(
      runNmapScan({
        target: 'nmap-rebind.invalid',
        dnsLookup: async () => [{ address: 'fe80::1', family: 6 }]
      }),
      /Blocked SSRF/
    );

    // Valid LAN ranges pass scan guard
    const okCidr = await assertSafeScanTarget('10.42.0.0/16', { allowPrivate: true });
    assert.equal(okCidr.isRange, true);
    const okOctetRange = await assertSafeScanTarget('192.168.1.1-254', { allowPrivate: true });
    assert.equal(okOctetRange.isRange, true);
  });

  it('netexec.js, kubeaudit.js (--remote), openvas.js, and kctf.js (testChallengeConnection) enforce SSRF/metadata guards', async () => {
    for (const badTarget of ['169.254.169.254', '169.0.0.0/8', 'fe80::1', 'fd00:ec2::254', 'metadata.google.internal']) {
      await assert.rejects(runNetexecAudit(badTarget, 'smb-signing'), /Blocked SSRF/);
      await assert.rejects(probeAuthProtocolsNative(badTarget), /Blocked SSRF/);
      await assert.rejects(runKubeAudit(badTarget, 'kube-hunter'), /Blocked SSRF/);
      await assert.rejects(runHostVulnerabilityScan({ host: badTarget, simulate: true }), /Blocked SSRF/);
    }

    // Synchronous kube-hunter buildArgs rejects metadata literals too
    const khProfile = KUBEAUDIT_PROFILES.find((p) => p.id === 'kube-hunter');
    assert.throws(() => khProfile.buildArgs('169.254.169.254'), /Blocked SSRF/);
    assert.throws(() => khProfile.buildArgs('fe80::1'), /Blocked SSRF/);

    // kctf.js testChallengeConnection blocks metadata, DNS rebinding, and pins valid connections
    await assert.rejects(testChallengeConnection({ host: '169.254.169.254', port: 80 }), /Blocked SSRF/);
    await assert.rejects(testChallengeConnection({ host: '[fd00:ec2::254]', port: 80 }), /Blocked SSRF/);
    await assert.rejects(
      testChallengeConnection({
        host: 'chal-rebind.invalid',
        port: 31337,
        dnsLookup: async () => [{ address: '169.254.169.254', family: 4 }]
      }),
      /Blocked SSRF/
    );
    await assert.rejects(testChallengeConnection({ host: '127.0.0.1', port: 99999 }), /Invalid port/);

    const tcpSrv = net.createServer((sock) => sock.end());
    await new Promise((resolve) => tcpSrv.listen(0, '127.0.0.1', resolve));
    const tcpPort = tcpSrv.address().port;
    try {
      const connOk = await testChallengeConnection({
        host: 'chal-pinned.invalid',
        port: tcpPort,
        dnsLookup: async () => [{ address: '127.0.0.1', family: 4 }]
      });
      assert.equal(connOk.success, true);
    } finally {
      await new Promise((resolve) => tcpSrv.close(resolve));
    }
  });
});

describe('SEC-H40, M41, M42, M44, M46, L14, L16: Secret masking, permissions, hardening, timingSafeEqual & collision avoidance', () => {
  it('trivy.js validates severity/namespace, pins image & hardens docker args, masks secrets, and enforces 0700/0600 modes', async () => {
    // M41 severity & namespace validation
    const imgProfile = TRIVY_PROFILES.find((p) => p.id === 'image');
    const k8sProfile = TRIVY_PROFILES.find((p) => p.id === 'k8s');
    assert.throws(() => imgProfile.buildArgs('alpine:3.20', { severity: 'HIGH,--format' }), /Invalid trivy severity/);
    assert.throws(() => imgProfile.buildArgs('alpine:3.20', { severity: 'BOGUS' }), /Invalid trivy severity/);
    assert.throws(() => k8sProfile.buildArgs('cluster', { namespace: 'bad_ns!' }), /Invalid namespace/);
    await assert.rejects(runTrivyAudit('alpine:3.20', 'image', { severity: 'INVALID' }), /Invalid trivy severity/);

    // M41 pinned image (not :latest) + container hardening + :ro docker.sock only when requested
    assert.doesNotMatch(TRIVY_IMAGE, /:latest$/);
    assert.equal(TRIVY_IMAGE, 'aquasec/trivy:0.69.3');

    const secretDockerArgs = buildTrivyDockerArgs(TRIVY_PROFILES.find((p) => p.id === 'secrets'), '/tmp/src');
    assert.ok(secretDockerArgs.includes('--network') && secretDockerArgs.includes('none'));
    assert.ok(secretDockerArgs.includes('--cap-drop') && secretDockerArgs.includes('ALL'));
    assert.ok(secretDockerArgs.includes('no-new-privileges'));
    assert.ok(!secretDockerArgs.some((a) => a.includes('docker.sock')));

    const remoteImageArgs = buildTrivyDockerArgs(imgProfile, 'nginx:alpine');
    assert.ok(!remoteImageArgs.some((a) => a.includes('docker.sock')));

    const localDaemonArgs = buildTrivyDockerArgs(imgProfile, 'nginx:alpine', { localDaemon: true });
    assert.ok(localDaemonArgs.includes('/var/run/docker.sock:/var/run/docker.sock:ro'));
    assert.ok(localDaemonArgs.includes('--network') && localDaemonArgs.includes('none'));

    // H40 parseTrivyOutput masks sec.Match
    const secretVal = 'AKIAIOSFODNN7SUPERSECRETKEY';
    const rawTrivyJson = JSON.stringify({
      Results: [{
        Target: '.env',
        Secrets: [{
          RuleID: 'aws-access-key-id',
          Category: 'AWS',
          Title: 'AWS Access Key ID',
          Severity: 'CRITICAL',
          Match: secretVal,
          Code: { Lines: [{ Number: 1, Content: `AWS_KEY=${secretVal}`, IsCause: true }] }
        }]
      }]
    });
    const parsedDirect = parseTrivyOutput(rawTrivyJson);
    assert.equal(parsedDirect.secrets.length, 1);
    assert.equal(parsedDirect.secrets[0].match, '[REDACTED]');

    // End-to-end shim trivy execution: mask sec.Match + rawOutput + evidence + 0700/0600
    await withFakeBin(
      'trivy',
      `#!/usr/bin/env node
if (process.argv.includes('--version')) { console.log('Version: 0.69.3'); process.exit(0); }
console.log(${JSON.stringify(rawTrivyJson)});
`,
      async () => {
        const res = await runTrivyAudit('secret-app', 'secrets');
        const reportDisk = await fs.readFile(res.filePath, 'utf8');
        assert.ok(!reportDisk.includes(secretVal), 'saved Trivy report must mask secret');
        assert.ok(!res.rawOutput.includes(secretVal), 'rawOutput must mask secret');
        const dirMode = (await fs.stat(path.dirname(res.filePath))).mode & 0o777;
        const fileMode = (await fs.stat(res.filePath)).mode & 0o777;
        assert.equal(dirMode, 0o700);
        assert.equal(fileMode, 0o600);

        const evPath = path.join(getVigilanteConfigDir(), 'evidence', 'audits', 'secret-app', `${res.id}.json`);
        const evDisk = await fs.readFile(evPath, 'utf8');
        assert.ok(!evDisk.includes(secretVal), 'Evidence Vault Trivy report must mask secret');
        assert.equal((await fs.stat(evPath)).mode & 0o777, 0o600);
      }
    );
  });

  it('oobscan.js masks plaintext BMC passwords in .jsonl/vault/parsed output and writes 0600 files in 0700 dirs', async () => {
    const bmcPassword = 'SuperSecretBmcPassword99!';
    const rakpHash = '$rakp$1234567890abcdef$admin';
    const ndjsonLine1 = JSON.stringify({
      type: 'credential',
      host: '10.0.100.20',
      username: 'ADMIN',
      password: bmcPassword,
      service: 'ipmi'
    });
    const ndjsonLine2 = JSON.stringify({
      host: '10.0.100.20',
      rakp_hash: rakpHash,
      rakp_username: 'ADMIN'
    });

    const parsedDirect = parseOobReportContent(`${ndjsonLine1}\n${ndjsonLine2}\n`, 'oobscan-10.0.100.20-1.jsonl');
    assert.equal(parsedDirect.bmcs[0].creds[0].pass, '[REDACTED]');
    assert.ok(!JSON.stringify(parsedDirect).includes(bmcPassword));

    await withFakeBin(
      'oobscan',
      `#!/usr/bin/env node
const fs = require('node:fs');
if (process.argv.includes('version') || process.argv.includes('--version')) { console.log('oobscan version 1.0.0'); process.exit(0); }
const oIdx = process.argv.indexOf('-o');
const outFile = oIdx >= 0 ? process.argv[oIdx + 1] : null;
const content = ${JSON.stringify(`${ndjsonLine1}\n${ndjsonLine2}\n`)};
if (outFile) fs.writeFileSync(outFile, content);
console.log(content);
`,
      async () => {
        const res = await runOobScan({ target: '10.0.100.20', profile: 'standard' });
        const jsonlDisk = await fs.readFile(res.jsonlFilePath, 'utf8');
        assert.ok(!jsonlDisk.includes(bmcPassword), 'saved .jsonl must mask plaintext BMC password');
        assert.ok(!res.output.includes(bmcPassword), 'returned stdout must mask plaintext BMC password');
        assert.equal(res.parsed.bmcs[0].creds[0].pass, '[REDACTED]');
        assert.equal((await fs.stat(path.dirname(res.jsonlFilePath))).mode & 0o777, 0o700);
        assert.equal((await fs.stat(res.jsonlFilePath)).mode & 0o777, 0o600);
        assert.ok(res.hashcatFilePath && fsSync.existsSync(res.hashcatFilePath));
        assert.equal((await fs.stat(res.hashcatFilePath)).mode & 0o777, 0o600);

        const evPath = path.join(getVigilanteConfigDir(), 'evidence', 'out-of-band', '10.0.100.20', `${res.id}.jsonl`);
        const evDisk = await fs.readFile(evPath, 'utf8');
        assert.ok(!evDisk.includes(bmcPassword), 'Evidence Vault .jsonl must mask plaintext BMC password');
        assert.equal((await fs.stat(evPath)).mode & 0o777, 0o600);
      }
    );
  });

  it('pods.js openInSystemPager uses private 0700 mkdtemp dir + 0600 wx file and cleans up in finally', async () => {
    const captureFile = path.join(tempRoot, 'pager-capture.json');
    const prevPager = process.env.PAGER;
    await withFakeBin(
      'vigilante-test-pager',
      `#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const file = process.argv[2];
const fStat = fs.statSync(file);
const dStat = fs.statSync(path.dirname(file));
fs.writeFileSync(${JSON.stringify(captureFile)}, JSON.stringify({
  file,
  dir: path.dirname(file),
  dirMode: dStat.mode & 0o777,
  fileMode: fStat.mode & 0o777,
  content: fs.readFileSync(file, 'utf8')
}));
`,
      async () => {
        process.env.PAGER = 'vigilante-test-pager';
        try {
          openInSystemPager('secret pod logs', 'pod.log');
          const cap = JSON.parse(await fs.readFile(captureFile, 'utf8'));
          assert.equal(cap.dirMode, 0o700);
          assert.equal(cap.fileMode, 0o600);
          assert.equal(cap.content, 'secret pod logs');
          assert.equal(fsSync.existsSync(cap.dir), false, 'pager temp directory must be removed in finally');
        } finally {
          process.stdin.pause?.();
          if (prevPager === undefined) delete process.env.PAGER;
          else process.env.PAGER = prevPager;
        }
      }
    );
  });

  it('helm.js & openvas.js enforce assertDnsLabel(namespace) and resolvePathInside', async () => {
    await assert.rejects(
      resolveChartValuesArgs({ moduleId: 'vigil-soc', chartName: 'vigil', namespace: '../escape' }),
      /Invalid namespace/
    );
    await assert.rejects(
      resolveChartValuesArgs({ moduleId: '../../etc', chartName: 'passwd', namespace: 'default' }),
      /escapes its base directory/
    );

    const validArgs = await resolveChartValuesArgs({
      moduleId: 'vigil-soc',
      chartName: 'vigil',
      namespace: 'vigilante-ns'
    });
    assert.ok(Array.isArray(validArgs));
    await cleanupHelmTempValues(validArgs);

    await assert.rejects(getOpenVasCredentials({ namespace: 'bad_ns!' }), /Invalid namespace/);
    await assert.rejects(checkOpenVasStatus({ namespace: 'openvas -n kube-system' }), /Invalid namespace/);
  });

  it('ad-runner.js uses timingSafeEqual for flag verification', () => {
    const engine = new TournamentEngine({ secretKey: 'w3-ad-secret' });
    const t1 = engine.registerTeam({ name: 'TeamOne' });
    const t2 = engine.registerTeam({ name: 'TeamTwo' });
    engine.start();
    const runner = new AttackDefenseRunner({ tournamentEngine: engine, mockProbes: true });
    engine.adState.currentTick = 1;
    const validFlag = generateAdTickFlag({ teamId: t2.id, serviceId: 'ad-service-vault', tick: 1, secretKey: 'w3-ad-secret' });

    const wrongLen = runner.submitAttackFlag({ attackerTeamId: t1.id, flag: validFlag.slice(0, -1) + 'aa}' });
    assert.equal(wrongLen.success, false);
    assert.equal(wrongLen.reason, 'Invalid flag signature');

    const badSig = runner.submitAttackFlag({
      attackerTeamId: t1.id,
      flag: validFlag.slice(0, -2) + (validFlag.endsWith('aa}') ? 'bb}' : 'aa}')
    });
    assert.equal(badSig.success, false);
    assert.equal(badSig.reason, 'Invalid flag signature');

    const ok = runner.submitAttackFlag({ attackerTeamId: t1.id, flag: validFlag });
    assert.equal(ok.success, true);
  });

  it('L14: openvas.js & netexec.js avoid plaintext passwords in CLI argv', async () => {
    const cmd = gvmCliCommand('admin', 'TopSecretGvmPass!', '<get_version/>');
    assert.ok(!cmd.includes('TopSecretGvmPass!'), 'gvmCliCommand must not expose password in CLI string');
    assert.ok(!cmd.includes('--gmp-password'), 'gvmCliCommand must not pass --gmp-password flag');
    assert.match(cmd, /gvm-cli -c "\$cfg"/);
    const ini = buildGvmConfigIni('admin', 'TopSecretGvmPass!');
    assert.match(ini, /\[gmp\]\nusername = admin\npassword = TopSecretGvmPass!/);
    assert.throws(() => buildGvmConfigIni('admin', 'bad\npass'), /CR\/LF/);

    // netexec.js: passes 0600 temp file path to -p instead of plaintext password and cleans up
    const nxcCaptureFile = path.join(tempRoot, 'nxc-capture.json');
    const nxcSecret = 'NxcSecretPass42!';
    await withFakeBin(
      'netexec',
      `#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
if (process.argv.includes('--version')) { console.log('1.0.0'); process.exit(0); }
const pIdx = process.argv.indexOf('-p');
const pArg = pIdx >= 0 ? process.argv[pIdx + 1] : '';
const pStat = fs.statSync(pArg);
fs.writeFileSync(${JSON.stringify(nxcCaptureFile)}, JSON.stringify({
  argv: process.argv.slice(2),
  passFile: pArg,
  passDir: path.dirname(pArg),
  fileMode: pStat.mode & 0o777,
  dirMode: fs.statSync(path.dirname(pArg)).mode & 0o777,
  fileContent: fs.readFileSync(pArg, 'utf8')
}));
console.log('SMB 10.0.0.5 445 DC01 [*] Domain Policy');
`,
      async () => {
        await runNetexecAudit('10.0.0.5', 'pass-policy', { user: 'svc_audit', password: nxcSecret });
        const cap = JSON.parse(await fs.readFile(nxcCaptureFile, 'utf8'));
        assert.ok(!cap.argv.includes(nxcSecret), 'netexec argv must never contain plaintext password');
        assert.equal(cap.fileContent, nxcSecret);
        assert.equal(cap.dirMode, 0o700);
        assert.equal(cap.fileMode, 0o600);
        assert.equal(fsSync.existsSync(cap.passDir), false, 'netexec temp secret dir must be cleaned up');
      }
    );

    const directArgs = NETEXEC_PROFILES.find((p) => p.id === 'null-sessions').buildArgs('198.51.100.1');
    assert.deepEqual(directArgs, ['smb', '198.51.100.1', '-u', '', '-p', '']);
  });

  it('SEC-L16: kctf.js appends deterministic SHA-256 suffix so team_1, team-1, and team1 never collide', async () => {
    const s1 = sanitizeSafeTeamId('team_1');
    const s2 = sanitizeSafeTeamId('team-1');
    const s3 = sanitizeSafeTeamId('team1');
    assert.equal(new Set([s1, s2, s3]).size, 3);
    assert.equal(s1, sanitizeSafeTeamId('team_1'));

    const m1 = generateEphemeralSandboxManifest({
      teamId: 'team_1',
      challengeId: 'web-flag-leak',
      sandboxId: 'sbx-1',
      flag: 'VIGILANTE{test1}'
    });
    const m2 = generateEphemeralSandboxManifest({
      teamId: 'team-1',
      challengeId: 'web-flag-leak',
      sandboxId: 'sbx-2',
      flag: 'VIGILANTE{test2}'
    });
    assert.ok(m1.includes(`name: ${s1}-web-flag-leak`));
    assert.ok(m2.includes(`name: ${s2}-web-flag-leak`));
    assert.notEqual(s1, s2);

    const sbxA = await spawnEphemeralSandbox({ teamId: 'team_1', challengeId: 'web-flag-leak', mock: true });
    const sbxB = await spawnEphemeralSandbox({ teamId: 'team-1', challengeId: 'web-flag-leak', mock: true });
    const sbxC = await spawnEphemeralSandbox({ teamId: 'team1', challengeId: 'web-flag-leak', mock: true });
    assert.equal(new Set([sbxA.host, sbxB.host, sbxC.host]).size, 3);
  });
});
