import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

import { classifyIpRange, assertSafeOutboundTarget, parseIpv6BigInt } from '../src/engine/ssrf.js';
import { probePortsNative, probeHttpNative, runReconScan } from '../src/engine/recon.js';
import {
  runPing,
  runBenchmark,
  runMtr,
  runCurlHeaders,
  runDnsLookup,
  runTlsCertDump,
  runArpNeighLookup,
  runFullTriageCapture
} from '../src/engine/diagnostics.js';
import { createVigilanteMcpServer } from '../src/mcp/server.js';
import { verifyOidcToken, resetOidcCache } from '../src/engine/authz-oidc.js';
import { runZapScan } from '../src/engine/zap.js';
import { runNucleiScan, NUCLEI_PROFILES } from '../src/engine/nuclei.js';
import { probeServiceSla, AttackDefenseRunner, generateAdTickFlag } from '../src/engine/ad-runner.js';
import { compileMcpSecurityContext, sanitizeSocraticResponse } from '../src/engine/llm.js';
import { initCtfWorkspace } from '../src/engine/ctf-client.js';
import { TournamentEngine, TOURNAMENT_STATES } from '../src/engine/tournament.js';
import { initAuditLedger, appendLedgerEntry, verifyLedgerIntegrity, exportLegalChainOfCustody } from '../src/engine/ledger.js';
import { runAgentSocInvestigation } from '../src/engine/agent-soc.js';
import { matchCtiIndicators } from '../src/engine/cti.js';
import { buildSocketConnectionMatrix, detectAnomalousSocketConnections } from '../src/engine/observability.js';
import { buildHostDossier, getHostDossier } from '../src/engine/dossier.js';
import { conveneIncidentWarRoom, conductAgentDebateRound, calculateConsensusScore, WARROOM_ROLES } from '../src/engine/warroom.js';
import { checksec, findFormatStringOffset } from '../src/engine/ctf-tools.js';
import { compareNmapScans } from '../src/engine/nastymap/diff.js';
import { parseNmapXml } from '../src/engine/nastymap/parser.js';
import { isPrivateIp, geocodeIp } from '../src/engine/nastymap/geoip.js';
import { generateTopology } from '../src/engine/nastymap/topology.js';
import { initOwner, addPrincipal, invalidateAuthzCache } from '../src/engine/authz.js';
import { runAuthzCli } from '../src/cli/authz.js';
import { assertReadOnlyDataLakeSql, initDataLake, ingestSecurityEvents, queryDataLake, closeDataLake } from '../src/engine/datalake.js';
import { verifyEvidenceBundle } from '../src/engine/evidencepack.js';
import { buildProcessLineageTree, detectAnomalousProcessLineage } from '../src/engine/lineage.js';
import { buildCausalTimeline } from '../src/engine/timeline.js';
import { buildCompositeAttackGraph, findShortestAttackPath, calculateBlastRadius } from '../src/engine/attackgraph.js';
import { detectBeaconingPeriodicity, detectDnsTunneling } from '../src/engine/beaconing.js';
import { parseBloodhoundData } from '../src/engine/bloodhound.js';
import { calculateFileEntropy, triggerRansomwareContainment } from '../src/engine/ransomware.js';
import { generatePatchForFinding } from '../src/engine/remediation.js';
import { dissectIpPacket, dissectTcpSegment, dissectFullPacket, filterPacket, exportToPcap } from '../src/engine/sniffer.js';
import { convertMispToStix, mergeThreatFeeds, filterIndicators } from '../src/engine/stixmisp.js';
import { auditFileContent } from '../src/engine/audit.js';
import { parseSuricataEve, parseZeekConnLogs, replayPcap } from '../src/engine/traffic.js';
import { ScenarioEngine, splitCommandWords } from '../src/engine/scenarios.js';
import { sanitizeThreatJobName, generateThreatJobManifest } from '../src/engine/threats.js';
import { generateNistIncidentRecord, listNistIncidents } from '../src/engine/nist.js';
import { NETEXEC_PROFILES } from '../src/engine/netexec.js';
import { getClusterInfo } from '../src/engine/cluster.js';
import { getVigilanteConfigDir, getVigilanteNmapsDir, getVigilanteNucleiDir, getVigilanteTrivyDir, getVigilanteZapDir, getVigilanteReconDir, getVigilanteNetexecDir, getVigilantePcapDir, saveConfig } from '../src/engine/config.js';

let tempRoot;
let prevConfigDir;
let prevXdgHome;
let prevAllowPriv;
let prevCtfSecret;
let prevMcpToken;

before(async () => {
  tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-audit-test-'));
  prevConfigDir = process.env.VIGILANTE_CONFIG_DIR;
  prevXdgHome = process.env.XDG_CONFIG_HOME;
  prevAllowPriv = process.env.VIGILANTE_ALLOW_PRIVATE_TARGETS;
  prevCtfSecret = process.env.VIGILANTE_CTF_SECRET;
  prevMcpToken = process.env.VIGILANTE_MCP_TOKEN;

  process.env.VIGILANTE_CONFIG_DIR = path.join(tempRoot, 'cfg');
  process.env.XDG_CONFIG_HOME = tempRoot;
  delete process.env.VIGILANTE_ALLOW_PRIVATE_TARGETS;
  process.env.VIGILANTE_CTF_SECRET = 'test-ctf-secret-key-0123456789abcdef';
  delete process.env.VIGILANTE_MCP_TOKEN;
});

after(async () => {
  closeDataLake();
  invalidateAuthzCache();
  resetOidcCache();

  if (prevConfigDir === undefined) delete process.env.VIGILANTE_CONFIG_DIR;
  else process.env.VIGILANTE_CONFIG_DIR = prevConfigDir;
  if (prevXdgHome === undefined) delete process.env.XDG_CONFIG_HOME;
  else process.env.XDG_CONFIG_HOME = prevXdgHome;
  if (prevAllowPriv === undefined) delete process.env.VIGILANTE_ALLOW_PRIVATE_TARGETS;
  else process.env.VIGILANTE_ALLOW_PRIVATE_TARGETS = prevAllowPriv;
  if (prevCtfSecret === undefined) delete process.env.VIGILANTE_CTF_SECRET;
  else process.env.VIGILANTE_CTF_SECRET = prevCtfSecret;
  if (prevMcpToken === undefined) delete process.env.VIGILANTE_MCP_TOKEN;
  else process.env.VIGILANTE_MCP_TOKEN = prevMcpToken;

  await fs.rm(tempRoot, { recursive: true, force: true });
});

describe('SSRF Guard (ssrf.js, recon.js, diagnostics.js, mcp/server.js, scanners)', () => {
  it('classifies IPv4, mapped/NAT64 IPv6, AWS IMDSv6, and private ranges', () => {
    assert.equal(classifyIpRange('169.254.169.254'), 'metadata');
    assert.equal(classifyIpRange('::ffff:169.254.169.254'), 'metadata');
    assert.equal(classifyIpRange('::ffff:a9fe:a9fe'), 'metadata');
    assert.equal(classifyIpRange('64:ff9b::169.254.169.254'), 'metadata');
    assert.equal(classifyIpRange('64:ff9b::a9fe:a9fe'), 'metadata');
    assert.equal(classifyIpRange('fd00:ec2::254'), 'metadata');
    assert.equal(classifyIpRange('fe80::1'), 'metadata');
    assert.equal(classifyIpRange('fd12:3456:789a::1'), 'private');
    assert.equal(classifyIpRange('10.0.0.5'), 'private');
    assert.equal(classifyIpRange('100.64.1.1'), 'private');
    assert.equal(classifyIpRange('127.0.0.1'), 'loopback');
    assert.equal(classifyIpRange('::1'), 'loopback');
    assert.equal(classifyIpRange('93.184.216.34'), 'public');
    assert.ok(parseIpv6BigInt('64:ff9b::a9fe:a9fe') !== null);
  });

  it('assertSafeOutboundTarget enforces DNS rebinding, bare IPv6 ports, trailing dots, and metadata locks', async () => {
    await assert.rejects(
      assertSafeOutboundTarget('http://[::ffff:a9fe:a9fe]/latest/meta-data/'),
      /Blocked SSRF/
    );
    await assert.rejects(
      assertSafeOutboundTarget('http://metadata.google.internal./computeMetadata/v1/'),
      /Blocked SSRF/
    );
    await assert.rejects(
      assertSafeOutboundTarget('169.254.169.254', { allowBareHost: true, allowPrivate: true, allowLoopback: true }),
      /Blocked SSRF/
    );
    await assert.rejects(
      assertSafeOutboundTarget('https://rebind.test/api', {
        dnsLookup: async () => [{ address: '::ffff:169.254.169.254', family: 6 }]
      }),
      /Blocked SSRF/
    );

    const v6Ok = await assertSafeOutboundTarget('[2606:4700:4700::1111]:443', { allowBareHost: true });
    assert.equal(v6Ok.hostname, '2606:4700:4700::1111');

    const dnsOk = await assertSafeOutboundTarget('https://public.test./v1', {
      dnsLookup: async () => [{ address: '93.184.216.34', family: 4 }]
    });
    assert.equal(dnsOk.hostname, 'public.test');
  });

  it('recon.js rejects SSRF targets and invalid ports before network IO', async () => {
    await assert.rejects(probePortsNative('::ffff:169.254.169.254', [80]), /Blocked SSRF/);
    await assert.rejects(probePortsNative('93.184.216.34', [0]), /Invalid probe port/);
    await assert.rejects(probeHttpNative('http://[fd00:ec2::254]/latest'), /Blocked SSRF/);
    await assert.rejects(runReconScan('http://127.0.0.1:8080', 'web-probe'), /Blocked SSRF/);
  });

  it('diagnostics.js blocks metadata/private targets by default and honors allowPrivate only for RFC1918', async () => {
    await assert.rejects(runPing('169.254.169.254'), /Blocked SSRF/);
    await assert.rejects(runBenchmark('[::ffff:169.254.169.254]'), /Blocked SSRF/);
    await assert.rejects(runMtr('10.0.0.1'), /Blocked SSRF/);
    await assert.rejects(runCurlHeaders('127.0.0.1'), /Blocked SSRF/);
    await assert.rejects(runCurlHeaders('93.184.216.34', { path: 'no-slash' }), /Invalid HTTP probe path/);
    await assert.rejects(runDnsLookup('169.254.169.254'), /Blocked SSRF/);
    await assert.rejects(runTlsCertDump('[fd00:ec2::254]'), /Blocked SSRF/);
    await assert.rejects(runArpNeighLookup('10.0.0.1;id'), /Invalid/);
    await assert.rejects(runFullTriageCapture('169.254.169.254', { allowPrivate: true, allowLoopback: true }), /Blocked SSRF/);
  });

  it('authz-oidc.js blocks non-loopback HTTP, metadata jwks_uri, and remote-to-loopback jwks_uri', async () => {
    resetOidcCache();
    let hits = 0;
    const srv = http.createServer((req, res) => {
      hits++;
      if (req.url === '/.well-known/openid-configuration') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({
          issuer: `http://127.0.0.1:${srv.address().port}`,
          jwks_uri: 'http://[::ffff:169.254.169.254]/keys'
        }));
      }
    });
    await new Promise((resolve) => srv.listen(0, '127.0.0.1', resolve));
    const port = srv.address().port;
    const prevIssuer = process.env.VIGILANTE_OIDC_ISSUER;
    const prevCid = process.env.VIGILANTE_OIDC_CLIENT_ID;
    try {
      process.env.VIGILANTE_OIDC_ISSUER = `http://127.0.0.1:${port}`;
      process.env.VIGILANTE_OIDC_CLIENT_ID = 'client-1';
      const principal = await verifyOidcToken('header.payload.sig', { principals: [] });
      assert.equal(principal, null);
      assert.equal(hits, 1);

      resetOidcCache();
      process.env.VIGILANTE_OIDC_ISSUER = 'http://93.184.216.34/issuer';
      assert.equal(await verifyOidcToken('header.payload.sig', { principals: [] }), null);
    } finally {
      srv.close();
      if (prevIssuer === undefined) delete process.env.VIGILANTE_OIDC_ISSUER;
      else process.env.VIGILANTE_OIDC_ISSUER = prevIssuer;
      if (prevCid === undefined) delete process.env.VIGILANTE_OIDC_CLIENT_ID;
      else process.env.VIGILANTE_OIDC_CLIENT_ID = prevCid;
    }
  });

  it('zap.js, nuclei.js, and ad-runner.js enforce outbound SSRF checks and profile forwarding', async () => {
    await assert.rejects(runZapScan('http://[::ffff:a9fe:a9fe]/'), /Blocked SSRF/);
    await assert.rejects(runZapScan('https://example.com', 'spider', { zapBaseUrl: 'http://169.254.169.254:8080' }), /Blocked SSRF/);
    await assert.rejects(runNucleiScan('http://10.0.0.1', 'cves'), /Blocked SSRF/);
    const misconfigArgs = NUCLEI_PROFILES.find(p => p.id === 'misconfigs').buildArgs('https://example.com', { severity: 'high' });
    assert.ok(misconfigArgs.includes('-s') && misconfigArgs.includes('high'));
    await assert.rejects(probeServiceSla({ host: '169.254.169.254', port: 80 }), /Blocked SSRF/);
  });

  it('MCP Server connects cleanly, blocks SSRF tools, gates write tools, and confines sensitive files', async () => {
    const ownerRes = await initOwner({ name: 'root-owner' });
    const viewerRes = await addPrincipal({ name: 'readonly-viewer', role: 'viewer' });
    process.env.VIGILANTE_MCP_TOKEN = viewerRes.token;

    const server = createVigilanteMcpServer();
    const client = new Client({ name: 'test-client', version: '1.0.0' }, { capabilities: {} });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

    try {
      const tools = await client.listTools();
      assert.ok(tools.tools.length > 10);

      for (const [toolName, args] of [
        ['run_diagnostic', { tool: 'ping', host: '169.254.169.254' }],
        ['run_triage_capture', { host: '::ffff:a9fe:a9fe' }],
        ['run_recon_scan', { target: 'http://[fd00:ec2::254]' }],
        ['run_nuclei_scan', { target: '127.0.0.1' }],
        ['run_zap_scan', { targetUrl: 'http://[::ffff:169.254.169.254]' }],
        ['run_ad_sla_check', { targetHost: '169.254.169.254', targetPort: 80 }],
        ['run_nmap_scan', { target: '169.254.169.254' }],
        ['run_oob_scan', { target: 'metadata.google.internal' }]
      ]) {
        await assert.rejects(
          client.callTool({ name: toolName, arguments: args }),
          /Blocked SSRF|Access denied/i,
          `${toolName} should fail on SSRF target`
        );
      }

      // Viewer must be blocked on previously-unauthenticated mutating tools even when MCP writes are enabled
      const prevAllowWrite = process.env.VIGILANTE_MCP_ALLOW_WRITE;
      process.env.VIGILANTE_MCP_ALLOW_WRITE = '1';
      try {
        for (const [writeTool, args] of [
          ['deploy_canary_asset', { type: 'aws_key' }],
          ['investigate_incident', { target: 'web-pod' }],
          ['broadcast_mesh_threat', { indicator: '198.51.100.1', indicatorType: 'IP' }]
        ]) {
          await assert.rejects(
            client.callTool({ name: writeTool, arguments: args }),
            /denied by Vigilante authz.*deny_missing_grant/i,
            `${writeTool} must reject viewer role`
          );
        }
      } finally {
        if (prevAllowWrite === undefined) delete process.env.VIGILANTE_MCP_ALLOW_WRITE;
        else process.env.VIGILANTE_MCP_ALLOW_WRITE = prevAllowWrite;
      }

      // Confine ctf-sandboxes.json and cert private keys in configDir
      const cfgDir = getVigilanteConfigDir();
      await fs.mkdir(path.join(cfgDir, 'instances', 'demo', 'certs'), { recursive: true });
      await fs.writeFile(path.join(cfgDir, 'ctf-sandboxes.json'), '[]');
      await fs.writeFile(path.join(cfgDir, 'instances', 'demo', 'certs', 'test-key.pem'), 'KEY');
      // Elevate temporarily to owner to verify path confinement rules themselves
      process.env.VIGILANTE_MCP_TOKEN = ownerRes.secret;
      await assert.rejects(
        client.callTool({
          name: 'ctf_triage_binary',
          arguments: { binaryPath: path.join(cfgDir, 'instances', 'demo', 'certs', 'test-key.pem') }
        }),
        /sensitive config file|forbidden/i
      );

      await assert.rejects(
        client.callTool({
          name: 'ctf_triage_binary',
          arguments: { binaryPath: path.join(cfgDir, 'ctf-sandboxes.json') }
        }),
        /sensitive config file|forbidden/i
      );
    } finally {
      delete process.env.VIGILANTE_MCP_TOKEN;
      await client.close();
      await server.close();
    }
  });
});

describe('High & Medium Vigilante Engine Fixes', () => {
  it('ad-runner.js scores previous tick after captures and uses team host instead of hardcoded 127.0.0.1', async () => {
    const engine = new TournamentEngine({ secretKey: 'ad-secret-123' });
    const t1 = engine.registerTeam({ name: 'Alpha' });
    const t2 = engine.registerTeam({ name: 'Beta' });
    t1.host = '10.10.1.1';
    t2.host = '10.10.2.2';
    engine.start();
    const runner = new AttackDefenseRunner({
      tournamentEngine: engine,
      defensePointsPerTick: 100,
      attackPointsPerCapture: 150,
      mockProbes: true
    });

    // Tick 1: injects flags for round 1
    const tick1 = await runner.executeTick();
    assert.equal(tick1.tick, 1);
    const betaServiceFlag = tick1.services[t2.id]['ad-service-vault'].flag;

    // Attacker t1 captures t2's tick-1 flag before tick 2 runs
    const sub = runner.submitAttackFlag({ attackerTeamId: t1.id, flag: betaServiceFlag });
    assert.equal(sub.success, true);
    assert.equal(t1.adAttackScore, 150);

    // Tick 2: now evaluates Tick 1's defense points! t2 was captured -> 0 defense pts; t1 uncaptured -> +100
    await runner.executeTick();
    assert.equal(t1.adDefenseScore, 100);
    assert.equal(t2.adDefenseScore, 0);

    // Test direct generated tick flag matches
    const forged = generateAdTickFlag({ teamId: t1.id, serviceId: 'ad-service-vault', tick: 1, secretKey: 'ad-secret-123' });
    assert.match(forged, /^VIGILANTE\{ad__/);
  });

  it('dossier.js ingests Nmap/Recon/Nuclei/Trivy/NetExec/ZAP/Traffic without double-counting or path traversal', async () => {
    const nmapDir = getVigilanteNmapsDir();
    const reconDir = getVigilanteReconDir();
    const nucleiDir = getVigilanteNucleiDir();
    const trivyDir = getVigilanteTrivyDir();
    const netexecDir = getVigilanteNetexecDir();
    const zapDir = getVigilanteZapDir();
    const pcapDir = getVigilantePcapDir();
    for (const d of [nmapDir, reconDir, nucleiDir, trivyDir, netexecDir, zapDir, pcapDir]) {
      await fs.mkdir(d, { recursive: true });
    }

    await fs.writeFile(path.join(nmapDir, 'n1.json'), JSON.stringify({
      target: '192.0.2.50',
      hosts: [{ ip: '192.0.2.50', openPorts: [22], bestOsMatch: { name: 'Linux 6.1' } }]
    }));
    await fs.writeFile(path.join(reconDir, 'r1.json'), JSON.stringify({
      target: '192.0.2.50',
      openPorts: [{ host: '192.0.2.50', port: 443 }],
      webServices: [{ url: 'https://192.0.2.50', status: 200, title: 'App' }]
    }));
    // One single critical CVE from Nuclei (+35), MUST NOT also count as Trivy (+30)!
    await fs.writeFile(path.join(nucleiDir, 'nuc1.json'), JSON.stringify({
      target: '192.0.2.50',
      findings: [{ templateId: 'CVE-2025-1', name: 'TestCrit', severity: 'critical', matchedAt: 'https://192.0.2.50', cveId: 'CVE-2025-1' }]
    }));
    await fs.writeFile(path.join(trivyDir, 'tri1.json'), JSON.stringify({
      target: '192.0.2.50',
      vulnerabilities: [{ cveId: 'CVE-2024-9', pkgName: 'openssl', fixedVersion: '3.1', severity: 'HIGH' }],
      secrets: []
    }));
    await fs.writeFile(path.join(netexecDir, 'ne1.json'), JSON.stringify({
      target: '192.0.2.50',
      findings: [{ ip: '192.0.2.50', smbSigning: 'False', isVulnerableToRelay: true }]
    }));
    await fs.writeFile(path.join(zapDir, 'zap1.json'), JSON.stringify({
      target: 'https://192.0.2.50',
      alerts: [{ alert: 'Missing CSP Header', risk: 'Medium', solution: 'Add CSP' }]
    }));

    const dossier = await buildHostDossier('192.0.2.50', {
      trafficAlerts: [{ srcIp: '192.0.2.50', severity: 'medium', signature: 'ET SCAN' }]
    });
    assert.deepEqual(dossier.network.openPorts, [22, 443]);
    assert.equal(dossier.network.osGuessed, 'Linux 6.1');
    assert.equal(dossier.network.httpEndpoints.length, 1);
    assert.equal(dossier.vulnerabilities.cves.length, 2);
    assert.equal(dossier.traffic.alertCount, 1);
    assert.ok(dossier.mitreTechniques.includes('T1557.001'));
    // Nuclei critical (35) + Trivy high (15) + NetExec signing (25) + ZAP Medium (10) = 85 (NOT 100 from double-counting Nuclei under Trivy!)
    assert.equal(dossier.riskScore, 85);

    const fetched = await getHostDossier('../../evil');
    assert.equal(fetched.cleanTarget, '.._.._evil');
    assert.ok(fsSync.existsSync(path.join(getVigilanteConfigDir(), 'dossiers', '.._.._evil.json')));
  });

  it('llm.js compileMcpSecurityContext reads Nmap/Evidence schema cleanly and Socratic sanitizer strips flags', async () => {
    const nmapDir = getVigilanteNmapsDir();
    await fs.writeFile(path.join(nmapDir, 'ctx.xml'), `<?xml version="1.0"?>
<nmaprun scanner="nmap"><host starttime="1" endtime="2"><status state="up"/>
<address addr="198.51.100.7" addrtype="ipv4"/>
<hostnames><hostname name="edge.example" type="user"/></hostnames>
<ports><port protocol="tcp" portid="8443"><state state="open"/><service name="https-alt"/></port></ports>
</host></nmaprun>`);
    const ctx = await compileMcpSecurityContext();
    assert.match(ctx, /edge\.example/);
    assert.match(ctx, /8443\/tcp \(https-alt\)/);
    assert.doesNotMatch(ctx, /\[object Object\]/);
    assert.equal(sanitizeSocraticResponse('Look near VIGILANTE{abc_123}!'), 'Look near [REDACTED_BY_SOCRATIC_MENTOR_GUARDRAIL]!');
  });

  it('ctf-client.js sanitizes traversal paths & tournament.js enforces XSS, export redaction, freeze & hint penalty', async () => {
    const ws = await initCtfWorkspace({
      targetDir: path.join(tempRoot, 'ctf-ws'),
      tournamentUrl: "https://ctf.example/'; import os; #",
      challenges: [{ id: '../../escape-chal', category: 'web', name: 'EscapeTest', port: 9000 }]
    });
    assert.equal(ws.scaffoldedCount, 1);
    assert.ok(!fsSync.existsSync(path.join(tempRoot, 'escape-chal')));

    const tourney = new TournamentEngine({ secretKey: 'tourney-secret-key' });
    const team = tourney.registerTeam({ name: '<script>alert(1)</script>' });
    const chal = tourney.addChallenge({
      id: 'pwn-1',
      name: 'Pwn 1',
      defaultFlag: 'VIGILANTE{real_flag_99}',
      isDynamicFlag: false,
      hints: [{ id: 'h1', text: 'Check GOT', cost: 75 }]
    });
    tourney.start();

    // Unlock Tier 2 hint (10% = 50 pts) at score 0 -> accrued pending penalty
    const hintRes = tourney.unlockHint({ teamId: team.id, challengeId: chal.id, tier: 2 });
    assert.equal(hintRes.success, true);
    assert.equal(team.score, 0);

    // Solve -> hint penalty deducted from awarded points!
    const solveRes = tourney.submitFlag({ teamId: team.id, challengeId: chal.id, flag: 'VIGILANTE{real_flag_99}' });
    assert.equal(solveRes.success, true);
    assert.ok(solveRes.hintPenaltyApplied > 0);
    assert.equal(team.score, solveRes.points);
    assert.ok(team.score > 0 && team.score < solveRes.basePoints + solveRes.firstBloodBonus);
    assert.equal(team.unlockedHints[0].unappliedPenalty, 0);

    // SVG escapes team name
    const svg = tourney.renderScoreCurvesSvg();
    assert.match(svg, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
    assert.doesNotMatch(svg, /<script>/);

    // Freeze hiding
    tourney.state = TOURNAMENT_STATES.FROZEN;
    const c2 = tourney.addChallenge({ id: 'web-2', name: 'Web 2', defaultFlag: 'VIGILANTE{frozen_flag}', isDynamicFlag: false });
    tourney.submitFlag({ teamId: team.id, challengeId: c2.id, flag: 'VIGILANTE{frozen_flag}' });
    const publicBoard = tourney.getLeaderboard({ revealFrozen: false });
    const adminBoard = tourney.getLeaderboard({ revealFrozen: true });
    assert.ok(adminBoard[0].totalScore > publicBoard[0].totalScore);
    assert.equal(publicBoard[0].solvesCount, 1);
    assert.equal(adminBoard[0].solvesCount, 2);

    // Export strips secrets
    const exported = tourney.exportState();
    assert.equal('token' in exported.teams[0], false);
    assert.equal('defaultFlag' in exported.challenges[0], false);
  });

  it('ledger.js serializes concurrent appends, hashes signer fields, and rejects unknown custody exports', async () => {
    const ledgerDir = path.join(tempRoot, 'ledger');
    const prevLedgerSecret = process.env.VIGILANTE_LEDGER_SECRET;
    process.env.VIGILANTE_LEDGER_SECRET = 'test-ledger-secret-key-0123456789';
    try {
      await initAuditLedger(ledgerDir);
      await Promise.all(
        Array.from({ length: 6 }, (_, i) =>
          appendLedgerEntry('INCIDENT_VERDICT', { incidentId: 'INC-1', seq: i }, { id: 'soc-bot', role: 'responder', keyId: 'k1' }, { ledgerDir })
        )
      );
      const verified = await verifyLedgerIntegrity(ledgerDir);
      assert.equal(verified.valid, true);
      assert.equal(verified.count, 6);

      const emptyCustody = await exportLegalChainOfCustody('NON-EXISTENT-INCIDENT', ledgerDir);
      assert.deepEqual(emptyCustody.entries, []);

      // Tampering signer role must invalidate Merkle chain
      const ledgerFile = path.join(ledgerDir, 'ledger.jsonl');
      const lines = (await fs.readFile(ledgerFile, 'utf8')).trim().split('\n');
      const parsed0 = JSON.parse(lines[0]);
      parsed0.signer.role = 'superadmin';
      lines[0] = JSON.stringify(parsed0);
      await fs.writeFile(ledgerFile, lines.join('\n') + '\n');
      const tampered = await verifyLedgerIntegrity(ledgerDir);
      assert.equal(tampered.valid, false);
    } finally {
      if (prevLedgerSecret === undefined) delete process.env.VIGILANTE_LEDGER_SECRET;
      else process.env.VIGILANTE_LEDGER_SECRET = prevLedgerSecret;
    }
  });

  it('agent-soc.js reports NONE verdict on clean target and skips SOAR containment', async () => {
    const res = await runAgentSocInvestigation({
      target: '198.51.100.200',
      automatedContainment: true,
      triggerAlert: { title: 'Routine Telemetry Check', source: 'Cron' }
    });
    assert.equal(res.verdict.threatLevel, 'NONE');
    assert.equal(res.verdict.score, 0);
    assert.equal(res.containment, null);
  });

  it('cti.js avoids false substring positives and circular matches property', async () => {
    const hits = await matchCtiIndicators(['198.51.100.4', '.io', 'http', 'c2.malicious.io']);
    assert.equal(Array.isArray(hits), true);
    assert.notEqual(hits.matches, hits);
    assert.doesNotThrow(() => JSON.stringify(hits));
    assert.equal(hits.some(h => h.indicator === '198.51.100.4' || h.indicator === '.io' || h.indicator === 'http'), false);
    assert.equal(hits.some(h => h.indicator === 'c2.malicious.io' && h.type === 'MALICIOUS_DOMAIN'), true);
  });

  it('observability.js copies destNamespace so cross-namespace anomalies trigger', () => {
    const matrix = buildSocketConnectionMatrix([
      { srcPod: 'web-1', namespace: 'frontend', dstIp: '10.96.0.10', dstPort: 5432, destNamespace: 'payments', bytesSent: 500 }
    ]);
    assert.equal(matrix.connections[0].destNamespace, 'payments');
    const anomalies = detectAnomalousSocketConnections(matrix, { crossNamespaceAllowed: false });
    assert.ok(anomalies.some(a => a.type === 'UNAUTHORIZED_CROSS_NAMESPACE_TRAFFIC'));
  });

  it('warroom.js strengthens SRE dissent on destructive DELETE_POD instead of boosting approval', () => {
    const session = conveneIncidentWarRoom({ targetWorkload: 'payment-db', severity: 'HIGH', anomalyScore: 70 });
    const before = calculateConsensusScore(session.opinions);
    const debated = conductAgentDebateRound(session.opinions, { action: 'DELETE_POD', target: 'payment-db' });
    const afterScore = calculateConsensusScore(debated);
    const sreAfter = debated.find(o => o.role === WARROOM_ROLES.SRE_RELIABILITY);
    assert.equal(sreAfter.verdict, 'MONITOR');
    assert.ok(afterScore.consensusScore <= before.consensusScore);
  });

  it('ctf-tools.js detects Full RELRO via PT_DYNAMIC, survives bad ELF headers, and ignores echo in format probe', async () => {
    // Build minimal valid 64-bit little-endian ELF with PT_GNU_RELRO + PT_DYNAMIC(DT_FLAGS_1 = DF_1_NOW)
    const buf = Buffer.alloc(256, 0);
    buf.write('\x7fELF', 0, 'latin1');
    buf[4] = 2; // ELF64
    buf[5] = 1; // LE
    buf.writeUInt16LE(3, 16); // ET_DYN (PIE)
    buf.writeBigUInt64LE(64n, 32); // e_phoff = 64
    buf.writeUInt16LE(56, 54); // e_phentsize
    buf.writeUInt16LE(2, 56); // e_phnum = 2
    // PHDR 0: PT_GNU_RELRO (0x6474e552) at offset 64
    buf.writeUInt32LE(0x6474e552, 64);
    // PHDR 1: PT_DYNAMIC (2) at offset 120 -> points to file offset 192, size 32
    buf.writeUInt32LE(2, 120);
    buf.writeBigUInt64LE(192n, 120 + 8);
    buf.writeBigUInt64LE(32n, 120 + 32);
    // Dyn entry 0: DT_FLAGS_1 (0x6ffffffb), val 0x1 (DF_1_NOW)
    buf.writeBigInt64LE(0x6ffffffbn, 192);
    buf.writeBigUInt64LE(1n, 200);
    // Dyn entry 1: DT_NULL
    buf.writeBigInt64LE(0n, 208);

    const cs = await checksec(buf);
    assert.equal(cs.relro, 'Full RELRO');
    assert.equal(cs.pie, true);

    // Malformed phentsize = 0 must not hang or throw
    const badElf = Buffer.from(buf);
    badElf.writeUInt16LE(0, 54);
    const badRes = await checksec(badElf);
    assert.equal(badRes.isElf, true);

    // Format string probe ignores echoed marker and detects actual hex pointer at index 6
    const fmtRes = await findFormatStringOffset({
      maxDepth: 10,
      probeFn: async (payload) => payload.includes('%6$p') ? 'V1G1.0x31473156' : payload.replace(/%(\d+)\$p/, '0xdeadbeef')
    });
    assert.equal(fmtRes.matched, true);
    assert.equal(fmtRes.offset, 6);
  });

  it('engine/nastymap diff/parser/geoip/topology and cli/authz fixes work accurately', async () => {
    const diff = compareNmapScans(
      { hosts: [{ id: '1.1.1.1', ports: [{ portid: 53, protocol: 'tcp', state: 'open' }, { portid: 53, protocol: 'udp', state: 'open' }] }] },
      { hosts: [{ id: '1.1.1.1', ports: [{ portid: 53, protocol: 'tcp', state: 'open' }, { portid: 53, protocol: 'udp', state: 'closed' }] }] }
    );
    assert.equal(diff.modifiedHosts.length, 1);
    const udpDiff = diff.modifiedHosts[0].portDiffs.find(p => p.protocol === 'udp');
    assert.equal(udpDiff.changeType, 'modified');

    const parsed = parseNmapXml(`<?xml version="1.0"?>
<nmaprun scanner="nmap"><host starttime="1" endtime="2"><status state="up"/>
<address addr="198.51.100.8" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="445"><state state="open"/></port></ports>
<os><osmatch name="Windows Server 2022" accuracy="98"><osclass type="general purpose" vendor="Microsoft" osfamily="Windows" accuracy="98"/></osmatch></os>
<hostscript><script id="smb-vuln-ms17-010" output="VULNERABLE: MS17-010"/></hostscript>
</host></nmaprun>`);
    assert.equal(parsed.hosts[0].osFamily, 'Windows');
    assert.equal(parsed.hosts[0].vulnerabilitiesCount, 1);
    assert.equal(parsed.hosts[0].hostScripts.length, 1);

    assert.equal(isPrivateIp('fd00:ec2::254'), true);
    assert.equal(isPrivateIp('::ffff:10.1.2.3'), true);
    const geo = geocodeIp('2a00:1450:4001:800::200e');
    assert.equal(Number.isFinite(geo.lat), true);
    assert.equal(Number.isFinite(geo.lon), true);

    const topo = generateTopology({
      target: '198.51.100.0/24',
      hosts: [
        { id: '198.51.100.1', ipv4: '198.51.100.1', isUp: true, ports: [], trace: { hops: [{ ttl: 1, ipaddr: '' }] } },
        { id: '198.51.100.2', ipv4: '198.51.100.2', isUp: true, ports: [], trace: { hops: [{ ttl: 1, ipaddr: '' }] } }
      ]
    });
    const hopNodes = topo.nodes.filter(n => n.nodeType === 'hop');
    assert.equal(hopNodes.length, 2);

    // Repeatable --grant CLI flag
    const code = await runAuthzCli(['add', 'multi-grant-user', '--grant', 'scans:read', '--grant', 'forensics:read']);
    assert.equal(code, 0);
    invalidateAuthzCache();
    const { loadAuthzStore } = await import('../src/engine/authz.js');
    const loaded = loadAuthzStore();
    const multi = loaded.store.principals.find(p => p.name === 'multi-grant-user');
    assert.deepEqual(multi.grants.map(g => g.permission), ['scans:read', 'forensics:read']);
  });

  it('datalake, evidencepack, lineage, timeline, attackgraph, beaconing, bloodhound, ransomware, remediation, sniffer, stixmisp, audit, traffic, scenarios, threats, nist, netexec, cluster fixes', async () => {
    // datalake
    assert.throws(() => assertReadOnlyDataLakeSql("SELECT * FROM read_json_auto('/etc/passwd')"), /forbidden/i);
    assert.throws(() => assertReadOnlyDataLakeSql("SELECT * FROM sqlite_scan('/etc/passwd', 't')"), /forbidden/i);
    initDataLake({ customPath: path.join(tempRoot, 'dl.db') });
    assert.equal(ingestSecurityEvents('falco', [{ id: 'ev1', pod: 'api', severity: 'HIGH' }]), 1);
    const rows = await queryDataLake('SELECT id FROM security_events');
    assert.equal(rows.length, 1);

    // evidencepack missing rfc3161Token does not throw TypeError
    const bDir = path.join(tempRoot, 'bad-bundle');
    await fs.mkdir(bDir, { recursive: true });
    await fs.writeFile(path.join(bDir, 'evidence_manifest.json'), JSON.stringify({ bundleId: 'b1', caseNumber: 'c1', evidenceItems: [] }));
    const bundleCheck = await verifyEvidenceBundle(bDir);
    assert.equal(bundleCheck.valid, false);
    assert.ok(bundleCheck.failures.some(f => /RFC 3161/i.test(f)));

    // lineage & timeline pod scoping
    const tree = buildProcessLineageTree([
      { pid: 10, ppid: 0, comm: 'nginx', podName: 'pod-a', containerId: 'ca' },
      { pid: 20, ppid: 10, comm: 'sh', podName: 'pod-b', containerId: 'cb' }
    ]);
    assert.equal(detectAnomalousProcessLineage(tree).filter(a => a.type === 'WEB_SERVER_SHELL_SPAWNED').length, 0);
    const tl = buildCausalTimeline([
      { id: 't1', entity: 'pod-a', pid: 10, timestamp: 1000 },
      { id: 't2', entity: 'pod-b', ppid: 10, pid: 20, timestamp: 2000 }
    ]);
    assert.equal(tl.edges.filter(e => e.type === 'SPAWNED_BY').length, 0);

    // attackgraph
    const ag = buildCompositeAttackGraph(
      [{ ip: '192.0.2.10', openPorts: [443] }],
      [
        { name: 'ingress', tier: 'Edge', namespace: 'prod', hostIp: '192.0.2.10' },
        { name: 'db', tier: 'CrownJewel', namespace: 'prod' }
      ]
    );
    assert.ok(ag.edges.length > 0);
    assert.equal(findShortestAttackPath('nonexistent', 'nonexistent', ag).pathFound, false);
    const untrustedBlast = calculateBlastRadius('pod-ingress', {
      nodes: [{ id: 'pod-ingress', tier: 'Edge' }, { id: 'ext', tier: 'Untrusted' }],
      edges: [{ from: 'pod-ingress', to: 'ext', type: 'X', cost: 1 }],
      adjacency: new Map([['pod-ingress', [{ from: 'pod-ingress', to: 'ext', cost: 1 }]], ['ext', []]])
    });
    assert.equal(untrustedBlast.impactScore, 0);

    // beaconing
    const beacon = detectBeaconingPeriodicity([60, 60, 60, 60]);
    assert.equal(beacon.isBeaconing, true);
    assert.equal(beacon.stats.min, 60);
    assert.equal(beacon.stats.max, 60);
    const dnsTun = detectDnsTunneling(['a9f4c8b12d3e4f5a6b7c8d9e0f1a2b3c.evil.com.']);
    assert.equal(dnsTun.hasTunnelingThreat, true);

    // bloodhound group admincount
    const bh = parseBloodhoundData({
      meta: { type: 'groups' },
      data: [{ Properties: { name: 'DOMAIN ADMINS@CORP', admincount: true }, Members: [{ ObjectIdentifier: 'u1' }] }]
    });
    assert.equal(bh.groups.length, 1);
    assert.equal(bh.users.length, 0);

    // ransomware directory safety & staged status
    assert.equal(calculateFileEntropy(tempRoot), 0);
    const rCont = await triggerRansomwareContainment('test-pod', 'default', 123, { apply: false });
    assert.equal(rCont.containmentSuccess, false);
    assert.equal(rCont.stagedOnly, true);

    // remediation registry port preservation
    const rem = generatePatchForFinding(
      { ruleId: 'VIGIL-K8S-003', pinnedTag: '2.0.0' },
      'apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n  - name: c\n    image: registry:5000/org/app:latest\n',
      'yaml'
    );
    assert.equal(rem.modified, true);
    assert.match(rem.patchedContent, /registry:5000\/org\/app:2\.0\.0/);

    // sniffer
    const badIp = Buffer.alloc(24, 0);
    badIp[0] = 0x41; // ihl=4
    assert.equal(dissectIpPacket(badIp), null);
    const badTcp = Buffer.alloc(24, 0);
    badTcp[12] = 0x10; // dataOffset=4
    assert.equal(dissectTcpSegment(badTcp), null);
    assert.equal(filterPacket({ src: '10.0.0.1:8080', dst: '10.0.0.2:443', protocol: 'TCP', summary: '', layers: { transport: { srcPort: 8080, dstPort: 443 } } }, 'port 80'), false);
    // Craft full Ethernet + IPv4 + TCP + HTTP packet
    const httpPayload = Buffer.from('GET /super-long-http-endpoint-path HTTP/1.1\r\nHost: x\r\n\r\n');
    const tcpHdr = Buffer.alloc(20);
    tcpHdr.writeUInt16BE(12345, 0);
    tcpHdr.writeUInt16BE(80, 2);
    tcpHdr[12] = 0x50;
    const ipHdr = Buffer.alloc(20);
    ipHdr[0] = 0x45;
    ipHdr.writeUInt16BE(20 + 20 + httpPayload.length, 2);
    ipHdr[9] = 6;
    ipHdr[12] = 192; ipHdr[13] = 0; ipHdr[14] = 2; ipHdr[15] = 1;
    ipHdr[16] = 192; ipHdr[17] = 0; ipHdr[18] = 2; ipHdr[19] = 2;
    const ethHdr = Buffer.alloc(14);
    ethHdr.writeUInt16BE(0x0800, 12);
    const pkt = {
      ...dissectFullPacket(Buffer.concat([ethHdr, ipHdr, tcpHdr, httpPayload]), 1),
      timestamp: new Date('2026-01-01T00:00:00.000Z').toISOString()
    };
    assert.equal(pkt.protocol, 'HTTP');
    assert.ok(pkt.summary.length > 8 && pkt.summary.includes('/super-long-http-endpoint-path'));
    const pcapBytes = await exportToPcap([pkt], path.join(tempRoot, 'out.pcap'));
    assert.ok(pcapBytes > 24);

    // stixmisp
    const stix = convertMispToStix({ Event: { info: 'test', timestamp: '2026-05-01T12:00:00.000Z', Attribute: [] } });
    assert.equal(stix.objects[0].created, '2026-05-01T12:00:00.000Z');
    const merged = mergeThreatFeeds([
      { indicators: [{ iocType: 'ipv4', iocValue: '198.51.100.1', pattern: "[ipv4-addr:value = '198.51.100.1']", confidence: 90, validFrom: '2026-01-02T00:00:00.000Z' }] },
      { indicators: [{ iocType: 'ipv4', iocValue: '198.51.100.1', pattern: "[ipv4-addr:value = '198.51.100.1']", confidence: 85, validFrom: '2026-02-02T00:00:00.000Z' }] }
    ]);
    assert.equal(merged[0].lastSeen, '2026-02-02T00:00:00.000Z');
    assert.equal(filterIndicators(merged, { minConfidence: 88 }).length, 1);

    // audit.js arg-order
    const auditFindings = auditFileContent('# App Dockerfile comment\nFROM ubuntu:22.04\nUSER root\n', 'Dockerfile');
    assert.ok(auditFindings.some(f => f.ruleId === 'VIGIL-DOCKER-001'));

    // traffic.js must NOT read arbitrary file paths unless { fromFile: true } is explicitly passed
    const evePath = path.join(tempRoot, 'sample.eve.json');
    const eveLine = JSON.stringify({ event_type: 'alert', src_ip: '198.51.100.1', dest_ip: '10.0.0.1', alert: { severity: 1, signature: 'TEST' } });
    await fs.writeFile(evePath, `${eveLine}\n${eveLine}\n`);
    assert.equal(parseSuricataEve(evePath).alerts.length, 0);
    assert.equal(parseSuricataEve(evePath, { fromFile: true }).alerts.length, 2);
    const zeekJson = parseZeekConnLogs('{"id.orig_h":"10.0.0.1","id.resp_h":"10.0.0.2","id.resp_p":4444,"conn_state":"SF"}');
    const zeekTsv = parseZeekConnLogs('#separator \\x09\n#fields\tid.orig_h\tid.resp_h\tid.resp_p\tconn_state\n10.0.0.1\t10.0.0.2\t4444\tSF');
    assert.equal(zeekJson.suspiciousConnections.length, 1);
    assert.equal(zeekTsv.suspiciousConnections.length, 1);
    await assert.rejects(replayPcap(path.join(tempRoot, 'out.pcap'), { namespace: 'bad_ns!' }), /Invalid namespace/);

    // scenarios.js, threats.js, nist.js, netexec.js, cluster.js
    assert.throws(() => new ScenarioEngine().executeKubectl('get pods', 'bad ns'), /Invalid namespace/);
    assert.deepEqual(splitCommandWords("exec pod -- sh -c 'echo hi'"), ['exec', 'pod', '--', 'sh', '-c', 'echo hi']);
    const mf = generateThreatJobManifest({ id: 'Test_Playbook_1', name: 'T', events: [] });
    assert.match(mf, new RegExp(sanitizeThreatJobName('Test_Playbook_1')));

    const nistRec = generateNistIncidentRecord({ incidentId: 'NIST-INC-T1', networkCidr: '10.9.0.0/24', hostIp: '10.9.0.5', primaryVector: 'Web App' });
    assert.equal(nistRec.target.host, '10.9.0.5');
    const evHostDir = path.join(getVigilanteConfigDir(), 'evidence', 'incidents', '10.9.0.5');
    await fs.mkdir(evHostDir, { recursive: true });
    await fs.writeFile(path.join(evHostDir, 'NIST-INC-T1.json'), JSON.stringify(nistRec));
    const nistList = await listNistIncidents();
    assert.ok(nistList.some(r => r.incidentId === 'NIST-INC-T1'));

    const nullArgs = NETEXEC_PROFILES.find(p => p.id === 'null-sessions').buildArgs('198.51.100.1');
    assert.deepEqual(nullArgs, ['smb', '198.51.100.1', '-u', '', '-p', '']);

    // config.js saveConfig mode
    const savedCfgPath = path.join(getVigilanteConfigDir(), 'config.yaml');
    await saveConfig({ version: '1.0' });
    const mode = (await fs.stat(savedCfgPath)).mode & 0o777;
    assert.equal(mode, 0o600);

    // cluster.js does not fake k3s=true when no k3d/k3s/kubectl cluster exists
    const info = await getClusterInfo('definitely-nonexistent-cluster-9999');
    if (!fsSync.existsSync('/etc/rancher/k3s/k3s.yaml')) {
      assert.equal(typeof info.exists, 'boolean');
    }
  });
});
