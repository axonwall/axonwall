import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

import {
  getVigilanteConfigDir,
  getVigilanteDossiersDir,
  getVigilanteTrivyDir,
  getVigilanteOobscansDir,
  getVigilanteEvidenceDir,
  saveConfig
} from '../src/engine/config.js';
import { buildHostDossier } from '../src/engine/dossier.js';
import {
  createEvidenceBundle,
  verifyEvidenceBundle,
  canonicalJson,
  buildCanonicalEvidenceManifest
} from '../src/engine/evidencepack.js';
import { saveEvidenceFile, readEvidenceContent } from '../src/engine/evidence.js';
import { initCtfWorkspace, sealSolveEvidence } from '../src/engine/ctf-client.js';
import { captureContainerDiff } from '../src/engine/snapshot.js';
import { carveFilesFromPayload } from '../src/engine/forensics.js';
import { TournamentEngine } from '../src/engine/tournament.js';
import {
  initAuditLedger,
  appendLedgerEntry,
  verifyLedgerIntegrity,
  buildMerkleRoot,
  generateInclusionProof,
  verifyInclusionProof,
  exportLegalChainOfCustody
} from '../src/engine/ledger.js';
import { isGpgAvailable, signFile, verifyFileSignature } from '../src/engine/gpg.js';
import { resolveSafeLogFile, writeDebugLog } from '../src/utils/logger.js';

const execFileAsync = promisify(execFile);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ENGINE_LEDGER_URL = new URL('../src/engine/ledger.js', import.meta.url).href;

let tempRoot;
let prevEnv;

before(async () => {
  tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-wave3-test-'));
  prevEnv = {
    VIGILANTE_CONFIG_DIR: process.env.VIGILANTE_CONFIG_DIR,
    XDG_CONFIG_HOME: process.env.XDG_CONFIG_HOME,
    VIGILANTE_TSA_KEY: process.env.VIGILANTE_TSA_KEY,
    VIGILANTE_LEDGER_SECRET: process.env.VIGILANTE_LEDGER_SECRET,
    VIGILANTE_CTF_SECRET: process.env.VIGILANTE_CTF_SECRET
  };
  process.env.VIGILANTE_CONFIG_DIR = path.join(tempRoot, 'cfg');
  process.env.XDG_CONFIG_HOME = tempRoot;
  process.env.VIGILANTE_TSA_KEY = 'wave3-tsa-signing-key-0123456789abcdef';
  process.env.VIGILANTE_LEDGER_SECRET = 'wave3-ledger-secret-0123456789abcdef';
  process.env.VIGILANTE_CTF_SECRET = 'wave3-ctf-secret-0123456789abcdef';
});

after(async () => {
  for (const [k, v] of Object.entries(prevEnv)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  await fs.rm(tempRoot, { recursive: true, force: true });
});

describe('Wave 3 Forensics & Crypto Remediations', () => {
  it('[SEC-H40] dossier.js masks Trivy secrets and OOBScan credentials/RAKP hashes and enforces 0o700/0o600 perms', async () => {
    const trivyDir = getVigilanteTrivyDir();
    const oobDir = getVigilanteOobscansDir();
    const dossiersDir = getVigilanteDossiersDir();
    await fs.mkdir(trivyDir, { recursive: true });
    await fs.mkdir(oobDir, { recursive: true });
    await fs.mkdir(dossiersDir, { recursive: true, mode: 0o755 });
    await fs.chmod(dossiersDir, 0o755);

    const rawAwsKey = 'AKIAIOSFODNN7EXAMPLEKEY';
    const rawTrivySecret = 'super_secret_api_token_987654';
    const rawCodeLine = 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    const rawIpmiPass = 'Calv1n_Plaintext_BMC_Pass!';
    const rawRakpHash = '$rakp$2233445566778899aabbccddeeff001122334455';

    await fs.writeFile(path.join(trivyDir, 'scan.json'), JSON.stringify({
      target: '192.0.2.77',
      secrets: [
        {
          ruleId: 'aws-access-key-id',
          category: 'AWS',
          title: 'AWS Access Key ID',
          severity: 'CRITICAL',
          target: 'app/.env',
          match: rawAwsKey,
          secret: rawTrivySecret,
          Code: { Lines: [{ Number: 4, Content: rawCodeLine }] }
        }
      ]
    }));

    await fs.writeFile(path.join(oobDir, 'oob.json'), JSON.stringify({
      target: '192.0.2.77',
      bmcs: [
        {
          ip: '192.0.2.77',
          vendor: 'Dell',
          rakpHash: rawRakpHash,
          creds: [
            { user: 'root', pass: rawIpmiPass, protocol: 'ipmi', status: 'valid' },
            { username: 'admin', password: 'SecondPlaintextPassword!', protocol: 'redfish' }
          ],
          rakp: [
            { user: 'root', role: 'ADMINISTRATOR', cipher: 'RAKP-HMAC-SHA1', hashcat: rawRakpHash, hash: rawRakpHash, raw: { secret: rawRakpHash } }
          ]
        }
      ]
    }));

    // Pre-create dossier file with overly broad mode to confirm chmod(0o600)
    const dossierFile = path.join(dossiersDir, '192.0.2.77.json');
    await fs.writeFile(dossierFile, '{}', { mode: 0o644 });
    await fs.chmod(dossierFile, 0o644);

    const dossier = await buildHostDossier('192.0.2.77');

    // Risk score still reflects secret (25) + BMC (15) + RAKP dumped (35) = 75
    assert.equal(dossier.vulnerabilities.secrets.length, 1);
    assert.equal(dossier.outOfBand.detected, true);
    assert.equal(dossier.riskScore, 75);

    const persistedRaw = await fs.readFile(dossierFile, 'utf8');
    for (const leaked of [rawAwsKey, rawTrivySecret, rawCodeLine, rawIpmiPass, 'SecondPlaintextPassword!', rawRakpHash]) {
      assert.equal(persistedRaw.includes(leaked), false, `Persisted dossier leaked secret: ${leaked}`);
    }
    assert.equal(dossier.vulnerabilities.secrets[0].match, '[REDACTED]');
    assert.equal(dossier.vulnerabilities.secrets[0].title, 'AWS Access Key ID');
    assert.equal(dossier.outOfBand.details.creds[0].user, 'root');
    assert.equal(dossier.outOfBand.details.creds[0].pass, '[REDACTED]');
    assert.equal(dossier.outOfBand.details.creds[1].password, '[REDACTED]');
    assert.equal(dossier.outOfBand.details.rakpHash, '[REDACTED]');
    assert.equal(dossier.outOfBand.details.rakp[0].hashcat, '[REDACTED]');

    assert.equal((await fs.stat(dossiersDir)).mode & 0o777, 0o700);
    assert.equal((await fs.stat(dossierFile)).mode & 0o777, 0o600);
  });

  it('[SEC-H41][SEC-M43][SEC-M45] evidencepack.js hashes canonical full manifest, confines verify_bundle.js, uses timingSafeEqual, and enforces 0o700/0o600', async () => {
    const outDir = path.join(tempRoot, 'bundles-root');
    const pack = await createEvidenceBundle(
      {
        caseNumber: 'CASE-W3-100',
        title: 'Incident 100',
        investigatorName: 'Alice DFIR',
        timestamp: '2026-11-27T10:00:00.000Z'
      },
      [
        { filename: 'b_log.txt', content: 'second item content\n', type: 'LOG' },
        { filename: 'a_mem.bin', content: Buffer.from('first item content\n'), type: 'MEMORY' }
      ],
      { outputDir: outDir, signingKey: process.env.VIGILANTE_TSA_KEY }
    );

    assert.equal((await fs.stat(outDir)).mode & 0o777, 0o700);
    assert.equal((await fs.stat(pack.bundleDir)).mode & 0o777, 0o700);
    assert.equal((await fs.stat(pack.manifestPath)).mode & 0o777, 0o600);
    assert.equal((await fs.stat(path.join(pack.bundleDir, 'a_mem.bin'))).mode & 0o777, 0o600);
    assert.equal((await fs.stat(path.join(pack.bundleDir, 'b_log.txt'))).mode & 0o777, 0o600);

    // Both verifyEvidenceBundle and standalone verify_bundle.js pass on pristine bundle
    const validRes = await verifyEvidenceBundle(pack.bundleDir);
    assert.equal(validRes.valid, true, `Unexpected failures: ${validRes.failures.join('; ')}`);

    const cliOk = await execFileAsync(process.execPath, [pack.verifyNodePath], {
      env: { ...process.env, VIGILANTE_TSA_KEY: process.env.VIGILANTE_TSA_KEY }
    });
    assert.match(cliOk.stdout, /SUCCESS/);

    // Reordering JSON keys (without changing values) must still pass canonical verification
    const originalManifest = JSON.parse(await fs.readFile(pack.manifestPath, 'utf8'));
    const reversedKeysManifest = {
      chainOfCustody: Object.fromEntries(Object.entries(originalManifest.chainOfCustody).reverse()),
      rfc3161Token: {
        ...originalManifest.rfc3161Token,
        tstInfo: Object.fromEntries(Object.entries(originalManifest.rfc3161Token.tstInfo).reverse())
      },
      aggregateHash: originalManifest.aggregateHash,
      evidenceItems: [...originalManifest.evidenceItems].reverse(),
      standard: originalManifest.standard,
      exportedAt: originalManifest.exportedAt,
      caseNumber: originalManifest.caseNumber,
      bundleId: originalManifest.bundleId
    };
    await fs.writeFile(pack.manifestPath, JSON.stringify(reversedKeysManifest, null, 2));
    assert.equal((await verifyEvidenceBundle(pack.bundleDir)).valid, true);
    await execFileAsync(process.execPath, [pack.verifyNodePath], {
      env: { ...process.env, VIGILANTE_TSA_KEY: process.env.VIGILANTE_TSA_KEY }
    });

    // Tampering chainOfCustody, exportedAt, caseNumber, item.type, or aggregateHash MUST fail BOTH verifiers
    const tamperMutations = [
      (m) => { m.caseNumber = 'CASE-FORGED'; },
      (m) => { m.exportedAt = '2026-01-01T00:00:00.000Z'; },
      (m) => { m.chainOfCustody.investigator.name = 'Mallory'; },
      (m) => { m.evidenceItems[0].type = 'TAMPERED_TYPE'; },
      (m) => { m.aggregateHash = '0'.repeat(64); }
    ];
    for (const mutate of tamperMutations) {
      const m = structuredClone(originalManifest);
      mutate(m);
      await fs.writeFile(pack.manifestPath, JSON.stringify(m, null, 2));
      const res = await verifyEvidenceBundle(pack.bundleDir);
      assert.equal(res.valid, false);
      await assert.rejects(
        execFileAsync(process.execPath, [pack.verifyNodePath], {
          env: { ...process.env, VIGILANTE_TSA_KEY: process.env.VIGILANTE_TSA_KEY }
        })
      );
    }

    // Tampered HMAC signature (different length and same length) fails in verify_bundle.js & verifyEvidenceBundle
    const badSigManifest = structuredClone(originalManifest);
    badSigManifest.rfc3161Token.signature = 'deadbeef';
    await fs.writeFile(pack.manifestPath, JSON.stringify(badSigManifest, null, 2));
    assert.equal((await verifyEvidenceBundle(pack.bundleDir)).valid, false);
    await assert.rejects(
      execFileAsync(process.execPath, [pack.verifyNodePath], {
        env: { ...process.env, VIGILANTE_TSA_KEY: process.env.VIGILANTE_TSA_KEY }
      })
    );

    // Symlink escape & path traversal in verify_bundle.js MUST be rejected
    const outsideSecret = path.join(tempRoot, 'outside-secret.txt');
    const outsideHash = crypto.createHash('sha256').update('secret-outside').digest('hex');
    await fs.writeFile(outsideSecret, 'secret-outside');
    const escapeSymlink = path.join(pack.bundleDir, 'escape_link.txt');
    await fs.symlink(outsideSecret, escapeSymlink);

    const escapeManifest = structuredClone(originalManifest);
    escapeManifest.evidenceItems.push({
      filename: 'escape_link.txt',
      type: 'RAW',
      size: 14,
      sha256: outsideHash,
      acquiredAt: new Date().toISOString()
    });
    const canonStr = canonicalJson(buildCanonicalEvidenceManifest(escapeManifest));
    const newAgg = crypto.createHash('sha256').update(canonStr, 'utf8').digest('hex');
    escapeManifest.aggregateHash = newAgg;
    escapeManifest.rfc3161Token.tstInfo.messageImprint.hashedMessage = newAgg;
    escapeManifest.rfc3161Token.signature = crypto
      .createHmac('sha256', process.env.VIGILANTE_TSA_KEY)
      .update(canonicalJson(escapeManifest.rfc3161Token.tstInfo))
      .digest('hex');
    await fs.writeFile(pack.manifestPath, JSON.stringify(escapeManifest, null, 2));

    assert.equal((await verifyEvidenceBundle(pack.bundleDir)).valid, false);
    await assert.rejects(
      execFileAsync(process.execPath, [pack.verifyNodePath], {
        env: { ...process.env, VIGILANTE_TSA_KEY: process.env.VIGILANTE_TSA_KEY }
      }),
      (err) => /SYMLINK\/PATH ESCAPE|FAILED/i.test(`${err.stdout}\n${err.stderr}`)
    );

    // Path traversal filename in verify_bundle.js
    const travManifest = structuredClone(originalManifest);
    travManifest.evidenceItems[0].filename = '../outside-secret.txt';
    await fs.writeFile(pack.manifestPath, JSON.stringify(travManifest, null, 2));
    await assert.rejects(
      execFileAsync(process.execPath, [pack.verifyNodePath], {
        env: { ...process.env, VIGILANTE_TSA_KEY: process.env.VIGILANTE_TSA_KEY }
      }),
      (err) => /PATH TRAVERSAL REJECTED/i.test(`${err.stdout}\n${err.stderr}`)
    );
  });

  it('[SEC-M44][SEC-M45] evidence.js confines readEvidenceContent to evidenceDir and enforces 0o700/0o600', async () => {
    const saved = await saveEvidenceFile('10.20.0.0/24', '10.20.0.5', 'artifact.json', { ok: true });
    const hostDir = path.dirname(saved.filePath);
    assert.equal((await fs.stat(hostDir)).mode & 0o777, 0o700);
    assert.equal((await fs.stat(saved.filePath)).mode & 0o777, 0o600);

    // Overwrite pre-existing 0o644 file -> chmod to 0o600
    await fs.chmod(saved.filePath, 0o644);
    await saveEvidenceFile('10.20.0.0/24', '10.20.0.5', 'artifact.json', { ok: 'updated' });
    assert.equal((await fs.stat(saved.filePath)).mode & 0o777, 0o600);

    // Valid readEvidenceContent via object and relative path inside evidenceDir
    const c1 = await readEvidenceContent({ filePath: saved.filePath });
    assert.match(c1, /updated/);
    const relPath = path.relative(getVigilanteEvidenceDir(), saved.filePath);
    const c2 = await readEvidenceContent(relPath);
    assert.match(c2, /updated/);

    // Traversal, outside absolute path, symlink escape, and evidenceDir itself must throw
    const outsideFile = path.join(tempRoot, 'not-evidence.txt');
    await fs.writeFile(outsideFile, 'TOP_SECRET');
    const symlinkEscape = path.join(hostDir, 'link-out.txt');
    await fs.symlink(outsideFile, symlinkEscape);

    await assert.rejects(readEvidenceContent('../../not-evidence.txt'), /escapes its base directory/i);
    await assert.rejects(readEvidenceContent(outsideFile), /escapes its base directory/i);
    await assert.rejects(readEvidenceContent(symlinkEscape), /escapes its base directory/i);
    await assert.rejects(readEvidenceContent(getVigilanteEvidenceDir()), /strictly inside/i);
    await assert.rejects(readEvidenceContent(''), /required/i);
  });

  it('[SEC-M45] ctf-client.js sets 0o700/0o600, snapshot.js stream-hashes with caps, and forensics.js prevents TOCTOU/symlink overwrites', async () => {
    // ctf-client.js permissions (including pre-existing 0o644 files)
    const wsDir = path.join(tempRoot, 'ctf-ws-perms');
    await fs.mkdir(wsDir, { recursive: true, mode: 0o755 });
    await fs.chmod(wsDir, 0o755);
    const cfgJson = path.join(wsDir, '.vigilante-ctf.json');
    await fs.writeFile(cfgJson, '{}', { mode: 0o644 });
    await fs.chmod(cfgJson, 0o644);

    await initCtfWorkspace({ targetDir: wsDir, teamToken: 'tk_secret_team_token' });
    assert.equal((await fs.stat(wsDir)).mode & 0o777, 0o700);
    assert.equal((await fs.stat(cfgJson)).mode & 0o777, 0o600);

    const vaultDir = path.join(tempRoot, 'ctf-vault');
    const seal = await sealSolveEvidence({
      teamId: 'team_1',
      challengeId: 'chal_1',
      flag: 'VIGILANTE{test}',
      outputDir: vaultDir,
      ledgerDir: path.join(tempRoot, 'ctf-ledger')
    });
    assert.equal((await fs.stat(vaultDir)).mode & 0o777, 0o700);
    assert.equal((await fs.stat(seal.manifestFile)).mode & 0o777, 0o600);

    // snapshot.js streaming hash + maxFiles / maxTotalBytes caps
    const snapRoot = path.join(tempRoot, 'snap-rootfs');
    await fs.mkdir(path.join(snapRoot, 'tmp'), { recursive: true });
    await fs.writeFile(path.join(snapRoot, 'tmp', 'a.sh'), 'echo A\n'.padEnd(40, 'a'));
    await fs.writeFile(path.join(snapRoot, 'tmp', 'b.txt'), 'B'.repeat(40));
    await fs.writeFile(path.join(snapRoot, 'tmp', 'c.txt'), 'C'.repeat(40));

    const fullDiff = await captureContainerDiff(snapRoot);
    assert.equal(fullDiff.files.length, 3);
    assert.equal(fullDiff.truncated, false);
    assert.equal(fullDiff.summary.totalBytes, 120);
    const expectedHashA = crypto.createHash('sha256').update('echo A\n'.padEnd(40, 'a')).digest('hex');
    assert.equal(fullDiff.files.find(f => f.path.endsWith('a.sh')).sha256, expectedHashA);

    const cappedFiles = await captureContainerDiff(snapRoot, { maxFiles: 2 });
    assert.equal(cappedFiles.files.length, 2);
    assert.equal(cappedFiles.truncated, true);

    const cappedBytes = await captureContainerDiff(snapRoot, { maxTotalBytes: 85 });
    assert.equal(cappedBytes.files.length, 2);
    assert.equal(cappedBytes.summary.totalBytes, 80);
    assert.equal(cappedBytes.truncated, true);

    // forensics.js atomic O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW with 0o600 & symlink resistance
    const carveDir = path.join(tempRoot, 'carve-out');
    await fs.mkdir(carveDir, { recursive: true, mode: 0o755 });
    const victimPath = path.join(tempRoot, 'victim.txt');
    await fs.writeFile(victimPath, 'DO_NOT_OVERWRITE');
    await fs.symlink(victimPath, path.join(carveDir, 'payload.txt'));

    const httpResp = (body) =>
      `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename="payload.txt"\r\n\r\n${body}`;

    const [carve1, carve2] = await Promise.all([
      carveFilesFromPayload(httpResp('BODY_ONE'), { outputDir: carveDir }),
      carveFilesFromPayload(httpResp('BODY_TWO'), { outputDir: carveDir })
    ]);

    assert.equal(await fs.readFile(victimPath, 'utf8'), 'DO_NOT_OVERWRITE');
    assert.equal((await fs.stat(carveDir)).mode & 0o777, 0o700);
    assert.notEqual(carve1[0].filePath, carve2[0].filePath);
    assert.equal((await fs.stat(carve1[0].filePath)).mode & 0o777, 0o600);
    assert.equal((await fs.stat(carve2[0].filePath)).mode & 0o777, 0o600);
    const contents = new Set([
      await fs.readFile(carve1[0].filePath, 'utf8'),
      await fs.readFile(carve2[0].filePath, 'utf8')
    ]);
    assert.deepEqual(contents, new Set(['BODY_ONE', 'BODY_TWO']));
  });

  it('[SEC-M46] tournament.js uses constant-time comparisons for team tokens, collusion, and flag verification', () => {
    const engine = new TournamentEngine({ secretKey: 'm46-secret' });
    const t1 = engine.registerTeam({ name: 'TeamOne' });
    const t2 = engine.registerTeam({ name: 'TeamTwo' });
    const dynChal = engine.addChallenge({ id: 'dyn-1', name: 'Dyn', isDynamicFlag: true });
    const statChal = engine.addChallenge({ id: 'stat-1', name: 'Static', defaultFlag: 'VIGILANTE{static_ok}', isDynamicFlag: false });
    engine.start();

    assert.equal(engine.getTeam(t1.token), t1);
    assert.equal(engine.getTeam(t1.token.slice(0, -1) + (t1.token.endsWith('a') ? 'b' : 'a')), null);
    assert.equal(engine.getTeam('tk_short'), null);
    assert.equal(engine.getTeam(''), null);

    // Collusion detection via TeamOne submitting TeamTwo's dynamic flag
    const t2FlagRes = engine.submitFlag({ teamId: t2.id, challengeId: dynChal.id, flag: 'wrong' });
    assert.equal(t2FlagRes.success, false);
    const t2RealFlag = (() => {
      const h = crypto.createHmac('sha256', 'm46-secret').update(`${t2.id}:${dynChal.id}`).digest('hex').slice(0, 16);
      return `VIGILANTE{${dynChal.id}_${t2.id}_${h}}`;
    })();
    const collusionRes = engine.submitFlag({ teamId: t1.id, challengeId: dynChal.id, flag: t2RealFlag });
    assert.equal(collusionRes.success, false);
    assert.match(collusionRes.reason, /Security anomaly/i);

    // Valid static and dynamic solves
    const statOk = engine.submitFlag({ teamId: t1.id, challengeId: statChal.id, flag: 'VIGILANTE{static_ok}' });
    assert.equal(statOk.success, true);
    const t1RealFlag = (() => {
      const h = crypto.createHmac('sha256', 'm46-secret').update(`${t1.id}:${dynChal.id}`).digest('hex').slice(0, 16);
      return `VIGILANTE{${dynChal.id}_${t1.id}_${h}}`;
    })();
    assert.equal(engine.submitFlag({ teamId: t1.id, challengeId: dynChal.id, flag: t1RealFlag }).success, true);
  });

  it('[SEC-M47][SEC-M46][SEC-M45] ledger.js enforces RFC 6962 Merkle domain separation, odd promotion, strict custody verification, perms & OS lockfile', async () => {
    // 1. Merkle tree domain separation & odd-node promotion
    const single = buildMerkleRoot(['alpha']);
    const expectedSingle = crypto.createHash('sha256')
      .update(Buffer.concat([Buffer.from([0x00]), Buffer.from('alpha', 'utf8')]))
      .digest('hex');
    assert.equal(single.root, expectedSingle);
    assert.notEqual(single.root, 'alpha');

    // Second-preimage resistance: 2-leaf internal node hash cannot collide with 1-leaf raw concatenation
    const pair = buildMerkleRoot(['left', 'right']);
    const pairLevels = pair.treeLevels[0];
    const forgedLeaf = buildMerkleRoot([pairLevels[0] + pairLevels[1]]);
    assert.notEqual(pair.root, forgedLeaf.root);

    // Odd trailing node promoted without duplication (CVE-2012-2459)
    const three = buildMerkleRoot(['a', 'b', 'c']);
    const fourDup = buildMerkleRoot(['a', 'b', 'c', 'c']);
    assert.notEqual(three.root, fourDup.root);

    // Inclusion proofs verify for every index across odd and even tree sizes
    for (const leaves of [['a'], ['a', 'b'], ['a', 'b', 'c'], ['a', 'b', 'c', 'd', 'e'], ['1', '2', '3', '4', '5', '6', '7']]) {
      const { root } = buildMerkleRoot(leaves);
      for (let i = 0; i < leaves.length; i++) {
        const proofObj = generateInclusionProof(i, leaves);
        assert.equal(proofObj.root, root);
        assert.equal(verifyInclusionProof(proofObj.entryHash, proofObj.proof, proofObj.root), true);
        assert.equal(verifyInclusionProof('tampered', proofObj.proof, proofObj.root), false);
      }
    }

    // 2. Permissions, strict custody match, verifyLedgerIntegrity inside exportLegalChainOfCustody, and timingSafeEqual on signature
    const ledgerDir = path.join(tempRoot, 'ledger-w3');
    await fs.mkdir(ledgerDir, { recursive: true, mode: 0o755 });
    const ledgerFile = path.join(ledgerDir, 'ledger.jsonl');
    const metaFile = path.join(ledgerDir, 'metadata.json');
    await fs.writeFile(ledgerFile, '', { mode: 0o644 });
    await fs.writeFile(metaFile, '{}', { mode: 0o644 });

    await initAuditLedger(ledgerDir);
    assert.equal((await fs.stat(ledgerDir)).mode & 0o777, 0o700);
    assert.equal((await fs.stat(ledgerFile)).mode & 0o777, 0o600);
    assert.equal((await fs.stat(metaFile)).mode & 0o777, 0o600);

    await appendLedgerEntry('FORENSIC_CAPTURE', { incidentId: 'INC-1', note: 'first' }, { id: 'a' }, { ledgerDir });
    await appendLedgerEntry('FORENSIC_CAPTURE', { incidentId: 'INC-10', note: 'mentions INC-1' }, { id: 'a' }, { ledgerDir });
    await appendLedgerEntry('FORENSIC_CAPTURE', 'INC-1 string payload', { id: 'a' }, { ledgerDir });

    const custody = await exportLegalChainOfCustody('INC-1', ledgerDir);
    assert.equal(custody.entries.length, 1);
    assert.equal(custody.entries[0].payload.incidentId, 'INC-1');

    // Cross-process exclusive OS lockfile serialization
    const childScript = `
      import { appendLedgerEntry } from ${JSON.stringify(ENGINE_LEDGER_URL)};
      const ledgerDir = process.env.TEST_LEDGER_DIR;
      const prefix = process.env.TEST_WORKER_ID;
      for (let i = 0; i < 4; i++) {
        await appendLedgerEntry('MULTI_PROC', { incidentId: 'INC-MP', worker: prefix, i }, { id: prefix }, { ledgerDir });
      }
    `;
    await Promise.all([
      execFileAsync(process.execPath, ['--input-type=module', '-e', childScript], {
        env: { ...process.env, TEST_LEDGER_DIR: ledgerDir, TEST_WORKER_ID: 'procA' }
      }),
      execFileAsync(process.execPath, ['--input-type=module', '-e', childScript], {
        env: { ...process.env, TEST_LEDGER_DIR: ledgerDir, TEST_WORKER_ID: 'procB' }
      })
    ]);
    assert.equal(fsSync.existsSync(path.join(ledgerDir, '.ledger.lock')), false);
    const mpVerified = await verifyLedgerIntegrity(ledgerDir);
    assert.equal(mpVerified.valid, true);
    assert.equal(mpVerified.count, 11);

    // Stale lockfile recovery
    const staleLock = path.join(ledgerDir, '.ledger.lock');
    await fs.writeFile(staleLock, 'stale', { mode: 0o600 });
    const oldTime = new Date(Date.now() - 60000);
    await fs.utimes(staleLock, oldTime, oldTime);
    await appendLedgerEntry('STALE_RECOVERY', { incidentId: 'INC-1' }, { id: 'a' }, { ledgerDir, lockStaleMs: 500 });
    assert.equal(fsSync.existsSync(staleLock), false);
    assert.equal((await verifyLedgerIntegrity(ledgerDir)).valid, true);

    // Symlink at .ledger.lock must fail closed without touching target
    const symlinkTarget = path.join(tempRoot, 'lock-symlink-target.txt');
    await fs.writeFile(symlinkTarget, 'UNTOUCHED');
    await fs.symlink(symlinkTarget, staleLock);
    await assert.rejects(
      appendLedgerEntry('SYMLINK_LOCK', { incidentId: 'INC-1' }, { id: 'a' }, { ledgerDir }),
      /symlink ledger lockfile/i
    );
    await fs.unlink(staleLock);
    assert.equal(await fs.readFile(symlinkTarget, 'utf8'), 'UNTOUCHED');

    // Tamper signature -> verifyLedgerIntegrity fails & exportLegalChainOfCustody fails closed
    const lines = (await fs.readFile(ledgerFile, 'utf8')).trim().split('\n');
    const tampered0 = JSON.parse(lines[0]);
    tampered0.signature = '0'.repeat(64);
    lines[0] = JSON.stringify(tampered0);
    await fs.writeFile(ledgerFile, lines.join('\n') + '\n');
    assert.equal((await verifyLedgerIntegrity(ledgerDir)).valid, false);
    await assert.rejects(exportLegalChainOfCustody('INC-1', ledgerDir), /integrity verification failed/i);
  });

  it('[SEC-M48] gpg.js fails closed on untrusted keys unless TRUST_FULLY/ULTIMATE or matching primary fingerprint/keyId', async () => {
    const gpgReady = await isGpgAvailable();
    assert.equal(gpgReady, true, 'gpg binary required for SEC-M48 test');

    const signerHome = path.join(tempRoot, 'gpg-signer');
    const verifierHome = path.join(tempRoot, 'gpg-verifier');
    const otherHome = path.join(tempRoot, 'gpg-other');
    for (const d of [signerHome, verifierHome, otherHome]) {
      await fs.mkdir(d, { recursive: true, mode: 0o700 });
      await fs.chmod(d, 0o700);
    }

    const genKey = async (home, email, name) => {
      const batchFile = path.join(home, 'gen.batch');
      await fs.writeFile(batchFile, [
        '%no-protection',
        'Key-Type: eddsa',
        'Key-Curve: ed25519',
        `Name-Real: ${name}`,
        `Name-Email: ${email}`,
        '%commit',
        ''
      ].join('\n'));
      await execFileAsync('gpg', ['--batch', '--generate-key', batchFile], { env: { ...process.env, GNUPGHOME: home } });
      const { stdout } = await execFileAsync('gpg', ['--batch', '--list-keys', '--with-colons'], { env: { ...process.env, GNUPGHOME: home } });
      const fprLine = stdout.split('\n').find(l => l.startsWith('fpr:'));
      return fprLine.split(':')[9];
    };

    const signerFpr = await genKey(signerHome, 'signer@vigilante.local', 'Signer Key');
    const otherFpr = await genKey(otherHome, 'other@vigilante.local', 'Other Key');

    // Export signer public key into verifierHome WITHOUT assigning trust -> TRUST_UNDEFINED
    const { stdout: pubArmor } = await execFileAsync('gpg', ['--batch', '--armor', '--export', signerFpr], {
      env: { ...process.env, GNUPGHOME: signerHome }
    });
    const pubPath = path.join(tempRoot, 'signer-pub.asc');
    await fs.writeFile(pubPath, pubArmor);
    await execFileAsync('gpg', ['--batch', '--import', pubPath], { env: { ...process.env, GNUPGHOME: verifierHome } });

    const targetFile = path.join(tempRoot, 'evidence-gpg.txt');
    await fs.writeFile(targetFile, 'authentic-forensic-payload\n');
    const sigRes = await signFile(targetFile, { gnupgHome: signerHome, keyId: signerFpr });
    assert.equal(sigRes.success, true);

    // Ensure config.gpg.keyId is cleared
    await saveConfig({ gpg: { enabled: true, keyId: '', gnupgHome: '' } });

    // 1. TRUST_UNDEFINED with no pinned key MUST fail closed
    const untrustedRes = await verifyFileSignature(targetFile, sigRes.signaturePath, { gnupgHome: verifierHome });
    assert.equal(untrustedRes.isValid, false);
    assert.equal(untrustedRes.success, false);
    assert.equal(untrustedRes.trustLevel, 'TRUST_UNDEFINED');

    // 2. Explicit expectedFingerprint matching VALIDSIG primary-key fingerprint PASSES
    const pinnedRes = await verifyFileSignature(targetFile, sigRes.signaturePath, {
      gnupgHome: verifierHome,
      expectedFingerprint: signerFpr
    });
    assert.equal(pinnedRes.isValid, true);
    assert.equal(pinnedRes.fingerprint, signerFpr);

    // 3. Explicit expectedFingerprint for a DIFFERENT key MUST fail even when signed by TRUST_ULTIMATE key
    const wrongPinOnUltimate = await verifyFileSignature(targetFile, sigRes.signaturePath, {
      gnupgHome: signerHome,
      expectedFingerprint: otherFpr
    });
    assert.equal(wrongPinOnUltimate.isValid, false);

    // 4. TRUST_ULTIMATE in signerHome without explicit pin PASSES
    const ultimateRes = await verifyFileSignature(targetFile, sigRes.signaturePath, { gnupgHome: signerHome });
    assert.equal(ultimateRes.isValid, true);
    assert.equal(ultimateRes.trustLevel, 'TRUST_ULTIMATE');

    // 5. config.gpg.keyId set to 16-char long keyId PASSES; 8-char short keyId or email FAILS closed on TRUST_UNDEFINED
    await saveConfig({ gpg: { enabled: true, keyId: signerFpr.slice(-16), gnupgHome: '' } });
    assert.equal((await verifyFileSignature(targetFile, sigRes.signaturePath, { gnupgHome: verifierHome })).isValid, true);

    await saveConfig({ gpg: { enabled: true, keyId: signerFpr.slice(-8), gnupgHome: '' } });
    assert.equal((await verifyFileSignature(targetFile, sigRes.signaturePath, { gnupgHome: verifierHome })).isValid, false);

    await saveConfig({ gpg: { enabled: true, keyId: 'signer@vigilante.local', gnupgHome: '' } });
    assert.equal((await verifyFileSignature(targetFile, sigRes.signaturePath, { gnupgHome: verifierHome })).isValid, false);

    await saveConfig({ gpg: { enabled: false, keyId: '', gnupgHome: '' } });
  });

  it('[SEC-L16] logger.js validates dir uid, mode & 0o077 === 0, and non-symlink file uid in resolveSafeLogFile()', async () => {
    const uid = process.getuid();
    const logTestRoot = path.join(tempRoot, 'log-tests');
    await fs.mkdir(logTestRoot, { recursive: true });

    // Unsafe mode (0o755) dir must be rejected in favor of safe 0o700 fallback
    const unsafeModeDir = path.join(logTestRoot, 'unsafe-755');
    await fs.mkdir(unsafeModeDir, { recursive: true, mode: 0o755 });
    await fs.chmod(unsafeModeDir, 0o755);
    const safeFallbackDir = path.join(logTestRoot, 'safe-700');
    await fs.mkdir(safeFallbackDir, { recursive: true, mode: 0o700 });
    await fs.chmod(safeFallbackDir, 0o700);

    const picked = resolveSafeLogFile([
      [unsafeModeDir, path.join(unsafeModeDir, 'vigilante.log')],
      [safeFallbackDir, path.join(safeFallbackDir, 'vigilante.log')]
    ]);
    assert.equal(picked, path.join(safeFallbackDir, 'vigilante.log'));

    // Dangling symlink at log file path must be rejected (never skipped by existsSync)
    const symlinkDir = path.join(logTestRoot, 'symlink-file-dir');
    await fs.mkdir(symlinkDir, { recursive: true, mode: 0o700 });
    await fs.chmod(symlinkDir, 0o700);
    const danglingLog = path.join(symlinkDir, 'vigilante.log');
    const danglingTarget = path.join(logTestRoot, 'should-not-be-created.txt');
    await fs.symlink(danglingTarget, danglingLog);
    assert.equal(resolveSafeLogFile([[symlinkDir, danglingLog]]), null);
    assert.equal(fsSync.existsSync(danglingTarget), false);

    // Mismatched directory UID must be rejected
    assert.equal(
      resolveSafeLogFile([[safeFallbackDir, path.join(safeFallbackDir, 'vigilante.log')]], { getuid: () => uid + 1 }),
      null
    );

    // Mismatched existing file UID must be rejected
    const safeFile = path.join(safeFallbackDir, 'vigilante.log');
    await fs.writeFile(safeFile, 'ok\n', { mode: 0o600 });
    assert.equal(
      resolveSafeLogFile([[safeFallbackDir, safeFile]], {
        getuid: () => uid,
        lstatSync: (p) => {
          const st = fsSync.lstatSync(p);
          if (p === safeFile) {
            return {
              isSymbolicLink: () => false,
              isFile: () => true,
              isDirectory: () => false,
              uid: uid + 999,
              mode: st.mode
            };
          }
          return st;
        }
      }),
      null
    );

    // writeDebugLog works end-to-end when HOME points to clean isolated home
    const isolatedHome = path.join(logTestRoot, 'isolated-home');
    await fs.mkdir(isolatedHome, { recursive: true, mode: 0o700 });
    const prevHome = process.env.HOME;
    try {
      process.env.HOME = isolatedHome;
      writeDebugLog('INFO', 'WAVE3', 'Safe logger check');
      const expectedLog = path.join(isolatedHome, '.config', 'vigilante', 'vigilante.log');
      assert.match(await fs.readFile(expectedLog, 'utf8'), /Safe logger check/);
      assert.equal((await fs.stat(expectedLog)).mode & 0o777, 0o600);
      assert.equal((await fs.stat(path.dirname(expectedLog))).mode & 0o777, 0o700);
    } finally {
      if (prevHome === undefined) delete process.env.HOME;
      else process.env.HOME = prevHome;
    }
  });
});
