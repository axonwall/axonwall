import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import * as yaml from 'js-yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const modulesDir = path.resolve(__dirname, '..', 'src', 'modules');

function chartPath(mod, chartName = mod) {
  return path.join(modulesDir, mod, 'charts', chartName);
}

function helmLint(chart, extraArgs = []) {
  return execFileSync('helm', ['lint', chart, ...extraArgs], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe']
  });
}

function helmTemplateDocs(release, chart, extraArgs = []) {
  const rendered = execFileSync('helm', ['template', release, chart, '--namespace', release, ...extraArgs], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe']
  });
  return {
    raw: rendered,
    docs: yaml.loadAll(rendered).filter(Boolean)
  };
}

describe('Wave 3 Helm & K8s Security Remediations', () => {
  it('[SEC-C07] ZAP chart enforces API key Secret, strict addr regex, disabled ingress, IMDS NetworkPolicy, and non-root securityContext', () => {
    const chart = chartPath('zap');
    helmLint(chart);

    const { raw, docs } = helmTemplateDocs('zap', chart);
    assert.equal(docs.some((d) => d.kind === 'Ingress'), false, 'ZAP Ingress must be disabled by default');

    const secret = docs.find((d) => d.kind === 'Secret');
    assert.ok(secret, 'ZAP must generate a Secret when existingSecret is unset');
    assert.ok(secret.data?.ZAP_API_KEY, 'ZAP Secret must contain ZAP_API_KEY');
    const decodedKey = Buffer.from(secret.data.ZAP_API_KEY, 'base64').toString('utf8');
    assert.ok(decodedKey.length >= 24, 'Generated ZAP_API_KEY must be strong random string');

    const dep = docs.find((d) => d.kind === 'Deployment');
    assert.ok(dep, 'ZAP Deployment must be rendered');
    assert.equal(dep.spec.template.spec.automountServiceAccountToken, false);
    assert.equal(dep.spec.template.spec.securityContext?.runAsNonRoot, true);

    const zapContainer = dep.spec.template.spec.containers[0];
    assert.equal(zapContainer.securityContext?.allowPrivilegeEscalation, false);
    assert.ok(zapContainer.securityContext?.capabilities?.drop?.includes('ALL'));

    const apiKeyEnv = zapContainer.env?.find((e) => e.name === 'ZAP_API_KEY');
    assert.equal(apiKeyEnv?.valueFrom?.secretKeyRef?.name, secret.metadata.name);
    assert.equal(apiKeyEnv?.valueFrom?.secretKeyRef?.key, 'ZAP_API_KEY');

    const argsStr = (zapContainer.args || []).join(' ');
    assert.match(argsStr, /api\.key=\$\(ZAP_API_KEY\)/);
    assert.equal(raw.includes('api.disablekey=true'), false);
    assert.equal(raw.includes('api.addrs.addr.name=.*'), false);

    assert.throws(
      () => helmTemplateDocs('zap', chart, ['--set', 'api.allowedAddrs=.*']),
      /api\.allowedAddrs must not be wildcard/
    );
    assert.throws(
      () => helmTemplateDocs('zap', chart, ['--set', 'secret.create=false']),
      /existingSecret is required/
    );

    const np = docs.find((d) => d.kind === 'NetworkPolicy');
    assert.ok(np, 'ZAP NetworkPolicy must be rendered');
    assert.deepEqual(np.spec.policyTypes, ['Ingress', 'Egress']);
    const egressBlocks = np.spec.egress.flatMap((r) => r.to || []).map((t) => t.ipBlock).filter(Boolean);
    assert.ok(
      egressBlocks.some((b) => Array.isArray(b.except) && b.except.includes('169.254.169.254/32')),
      'ZAP NetworkPolicy egress must block 169.254.169.254/32'
    );
  });

  it('[SEC-C08] kCTF manifests replace ClusterRole with namespaced Role, harden portal & challenges, and pin image tags', () => {
    const manifestDir = path.join(modulesDir, 'kctf', 'manifests');
    const files = ['00-crd-challenges.yaml', '01-rbac.yaml', '02-kctf-portal.yaml', '03-sample-challenges.yaml'];
    const parsedByFile = new Map();

    for (const file of files) {
      const content = fs.readFileSync(path.join(manifestDir, file), 'utf8');
      const docs = yaml.loadAll(content).filter(Boolean);
      assert.ok(docs.length > 0, `${file} must contain YAML documents`);
      parsedByFile.set(file, { content, docs });
    }

    const rbacDocs = parsedByFile.get('01-rbac.yaml').docs;
    assert.equal(rbacDocs.some((d) => d.kind === 'ClusterRole' || d.kind === 'ClusterRoleBinding'), false);
    const role = rbacDocs.find((d) => d.kind === 'Role');
    const binding = rbacDocs.find((d) => d.kind === 'RoleBinding');
    assert.equal(role?.metadata?.namespace, 'kctf');
    assert.equal(binding?.metadata?.namespace, 'kctf');
    assert.equal(binding?.roleRef?.kind, 'Role');
    assert.equal(
      role.rules.some((r) => (r.resources || []).includes('secrets')),
      false,
      'kCTF Role must not grant secrets CRUD'
    );

    const portalDocs = parsedByFile.get('02-kctf-portal.yaml').docs;
    const portalDep = portalDocs.find((d) => d.kind === 'Deployment');
    assert.equal(portalDep.spec.template.spec.serviceAccountName, undefined);
    assert.equal(portalDep.spec.template.spec.automountServiceAccountToken, false);
    assert.equal(portalDep.spec.template.spec.securityContext?.runAsNonRoot, true);
    const portalC = portalDep.spec.template.spec.containers[0];
    assert.equal(portalC.securityContext?.allowPrivilegeEscalation, false);
    assert.ok(portalC.securityContext?.capabilities?.drop?.includes('ALL'));
    assert.equal(/:(latest|alpine)$/.test(portalC.image), false, `Portal image must be version-pinned: ${portalC.image}`);

    const chalEntry = parsedByFile.get('03-sample-challenges.yaml');
    const chalDeps = chalEntry.docs.filter((d) => d.kind === 'Deployment');
    assert.ok(chalDeps.length >= 8);
    for (const dep of chalDeps) {
      assert.equal(dep.spec.template.spec.automountServiceAccountToken, false, `${dep.metadata.name} must disable SA token automount`);
      assert.equal(dep.spec.template.spec.securityContext?.runAsNonRoot, true, `${dep.metadata.name} must enforce runAsNonRoot`);
      for (const c of dep.spec.template.spec.containers) {
        assert.equal(c.securityContext?.allowPrivilegeEscalation, false);
        assert.ok(c.securityContext?.capabilities?.drop?.includes('ALL'));
        assert.equal(/:(latest|alpine)$/.test(c.image), false, `${dep.metadata.name} image must be pinned: ${c.image}`);
      }
    }
    const chals = chalEntry.docs.filter((d) => d.kind === 'Challenge');
    for (const ch of chals) {
      for (const c of ch.spec?.podTemplate?.template?.spec?.containers || []) {
        assert.equal(/:(latest|alpine)$/.test(c.image), false, `Challenge ${ch.metadata.name} image must be pinned: ${c.image}`);
      }
    }
  });

  it('[SEC-H33] OpenVAS hardens init scripts, log/socket permissions, logLevel int coercion, securityContext, and NetworkPolicy', () => {
    const chart = chartPath('openvas');
    helmLint(chart);

    assert.throws(
      () => helmTemplateDocs('openvas', chart),
      /admin\.password or existingSecret is required/
    );

    const { raw, docs } = helmTemplateDocs('openvas', chart, ['--set', 'existingSecret=openvas-admin', '--set', 'logLevel=16']);

    const cm = docs.find((d) => d.kind === 'ConfigMap' && d.metadata.name === 'init-scripts-config');
    assert.ok(cm);
    for (const [key, script] of Object.entries(cm.data)) {
      execFileSync('sh', ['-n'], { input: script });
      assert.ok(script.length > 20, `${key} should be non-empty`);
    }

    const pgScript = cm.data['init-postgres.sh'];
    assert.equal(pgScript.includes('local all all trust'), false);
    assert.match(pgScript, /POSTGRES_HOST_AUTH_METHOD="scram-sha-256"/);
    assert.match(pgScript, /-v user="\$PG_USER" -v pass="\$PG_PASS"/);
    assert.equal(pgScript.includes('with superuser'), false);

    const adminScript = cm.data['bootstrap-admin.sh'];
    assert.equal(adminScript.includes('${ADMIN_PASSWORD:-admin}'), false);
    assert.match(adminScript, /if \[ -z "\$ADMIN_PASS" \]/);
    assert.match(adminScript, /exec \/usr\/local\/sbin\/gvmd --user="\$1" --new-password="\$2"/);
    assert.match(adminScript, /exec \/usr\/local\/sbin\/gvmd --create-user="\$1" --password="\$2"/);

    const dep = docs.find((d) => d.kind === 'Deployment');
    assert.equal(dep.spec.template.spec.automountServiceAccountToken, false);
    const configInit = dep.spec.template.spec.initContainers.find((c) => c.name === 'configure-openvas');
    assert.match(configInit.command.join('\n'), /sed "s\/127\/16\/"/);
    assert.match(configInit.command.join('\n'), /chmod 0640 \/var\/log\/openvas\/openvas\.log/);
    assert.equal(raw.includes('chmod 666'), false);

    // Ensure malicious logLevel string cannot inject sed commands (Sprig int coerces non-int to 0)
    const { docs: injDocs } = helmTemplateDocs('openvas', chart, ['--set', 'existingSecret=openvas-admin', '--set', 'logLevel=16/e;id']);
    const injDep = injDocs.find((d) => d.kind === 'Deployment');
    const injConfig = injDep.spec.template.spec.initContainers.find((c) => c.name === 'configure-openvas');
    assert.match(injConfig.command.join('\n'), /sed "s\/127\/0\/"/);

    const ospd = dep.spec.template.spec.containers.find((c) => c.name === 'ospd-openvas');
    assert.deepEqual(ospd.command.slice(-2), ['-m', '660']);
    assert.equal(raw.includes('"-m", "666"') || raw.includes('- "666"'), false);

    for (const c of [...dep.spec.template.spec.initContainers, ...dep.spec.template.spec.containers]) {
      assert.equal(c.securityContext?.allowPrivilegeEscalation, false, `${c.name} must disable privilege escalation`);
      assert.ok(c.securityContext?.capabilities?.drop?.includes('ALL'), `${c.name} must drop ALL capabilities`);
    }

    const np = docs.find((d) => d.kind === 'NetworkPolicy');
    assert.ok(np);
    assert.ok(JSON.stringify(np.spec.egress).includes('169.254.169.254/32'));
  });

  it('[SEC-M49] Wazuh moves secrets to Secret/lookup, enables hostname verification, and adds NetworkPolicies', () => {
    const chart = chartPath('wazuh');
    helmLint(chart);
    const { raw, docs } = helmTemplateDocs('wazuh', chart);

    assert.equal(raw.includes('SecretPassword'), false);
    assert.equal(raw.includes('MyS3cr37P450r'), false);

    const cm = docs.find((d) => d.kind === 'ConfigMap');
    assert.equal(cm.data['internal_users.yml'], undefined, 'internal_users.yml must not reside in ConfigMap');
    assert.match(cm.data['opensearch.yml'], /enforce_hostname_verification:\s*true/);

    const sec = docs.find((d) => d.kind === 'Secret');
    assert.ok(sec?.data?.INDEXER_PASSWORD);
    assert.ok(sec?.data?.DASHBOARD_PASSWORD);
    assert.ok(sec?.data?.API_PASSWORD);
    assert.ok(sec?.data?.['internal_users.yml']);
    const internalUsers = yaml.load(Buffer.from(sec.data['internal_users.yml'], 'base64').toString('utf8'));
    assert.match(internalUsers.admin.hash, /^\$2[aby]\$/);
    assert.match(internalUsers.kibanaserver.hash, /^\$2[aby]\$/);

    const dash = docs.find((d) => d.kind === 'Deployment' && d.metadata.name === 'wazuh-dashboard');
    assert.equal(dash.spec.template.spec.automountServiceAccountToken, false);
    for (const envName of ['INDEXER_PASSWORD', 'DASHBOARD_PASSWORD', 'API_PASSWORD']) {
      const entry = dash.spec.template.spec.containers[0].env.find((e) => e.name === envName);
      assert.equal(entry?.value, undefined);
      assert.equal(entry?.valueFrom?.secretKeyRef?.name, sec.metadata.name);
    }

    const mgr = docs.find((d) => d.kind === 'StatefulSet' && d.metadata.name === 'wazuh-manager');
    assert.equal(mgr.spec.template.spec.automountServiceAccountToken, false);
    for (const envName of ['INDEXER_PASSWORD', 'API_PASSWORD']) {
      const entry = mgr.spec.template.spec.containers[0].env.find((e) => e.name === envName);
      assert.equal(entry?.value, undefined);
      assert.equal(entry?.valueFrom?.secretKeyRef?.name, sec.metadata.name);
    }

    const idx = docs.find((d) => d.kind === 'StatefulSet' && d.metadata.name === 'wazuh-indexer');
    assert.equal(idx.spec.template.spec.automountServiceAccountToken, false);
    const secVol = idx.spec.template.spec.volumes.find((v) => v.name === 'security-users');
    assert.equal(secVol?.secret?.secretName, sec.metadata.name);

    const nps = docs.filter((d) => d.kind === 'NetworkPolicy');
    assert.ok(nps.length >= 4);
  });

  it('[SEC-M49] Vigil SOC enables hardened NetworkPolicies, CSRF/approval defaults, Redis auth, Bifrost secret isolation, and websecure', () => {
    const chart = chartPath('vigil-soc', 'vigil');
    const modValues = path.join(modulesDir, 'vigil-soc', 'values', 'vigil.yaml');
    helmLint(chart, ['--set', 'secrets.existingSecret=vigil-secrets']);

    assert.throws(
      () => helmTemplateDocs('vigil', chart),
      /secrets\.postgresPassword is required/
    );

    const chartVals = yaml.load(fs.readFileSync(path.join(chart, 'values.yaml'), 'utf8'));
    assert.equal(chartVals.networkPolicies.enabled, true);
    assert.equal(chartVals.networkPolicies.agentServe.allowProbesFromAnyNamespace, false);
    assert.equal(chartVals.config.VIGIL_CSRF_REPORT_ONLY, 'false');
    assert.equal(chartVals.config.DAEMON_FORCE_APPROVAL, 'true');
    assert.equal(chartVals.splunk.auth.password, '');
    assert.equal(chartVals.pgadmin.auth.password, '');

    const devVals = yaml.load(fs.readFileSync(path.join(chart, 'values-dev.yaml'), 'utf8'));
    assert.equal(devVals.secrets.postgresPassword, '');

    const modVals = yaml.load(fs.readFileSync(modValues, 'utf8'));
    assert.equal(modVals.ingress.annotations['traefik.ingress.kubernetes.io/router.entrypoints'], 'websecure');

    const { docs } = helmTemplateDocs('vigil', chart, [
      '-f', modValues,
      '--set', 'secrets.existingSecret=vigil-secrets',
      '--set', 'pgadmin.enabled=true',
      '--set', 'pgadmin.auth.existingSecret=pgadmin-secret'
    ]);

    const nps = docs.filter((d) => d.kind === 'NetworkPolicy');
    assert.ok(nps.length >= 8);
    for (const np of nps) {
      for (const ing of np.spec.ingress || []) {
        for (const from of ing.from || []) {
          assert.notDeepEqual(from, { namespaceSelector: {} }, `${np.metadata.name} must not have namespaceSelector: {} bypass`);
        }
      }
    }
    const denyAll = nps.find((d) => d.metadata.name.endsWith('-deny-all'));
    assert.ok(JSON.stringify(denyAll.spec.egress).includes('169.254.169.254/32'));
    assert.equal(denyAll.spec.egress.some((e) => Object.keys(e).length === 0), false);

    const redisSecret = docs.find((d) => d.kind === 'Secret' && d.metadata.name.endsWith('-redis-auth'));
    assert.ok(redisSecret?.data?.REDIS_PASSWORD);
    const redisSts = docs.find((d) => d.kind === 'StatefulSet' && d.metadata.name.endsWith('-redis'));
    assert.equal(redisSts.spec.template.spec.securityContext?.runAsNonRoot, true);
    assert.equal(redisSts.spec.template.spec.containers[0].securityContext?.allowPrivilegeEscalation, false);
    assert.ok(redisSts.spec.template.spec.containers[0].args.includes('--requirepass'));
    assert.ok(redisSts.spec.template.spec.containers[0].args.includes('$(REDIS_PASSWORD)'));

    const pgSts = docs.find((d) => d.kind === 'StatefulSet' && d.metadata.name.endsWith('-postgres'));
    assert.equal(pgSts.spec.template.spec.securityContext?.runAsNonRoot, true);
    assert.equal(pgSts.spec.template.spec.containers[0].securityContext?.allowPrivilegeEscalation, false);
    assert.ok(pgSts.spec.template.spec.containers[0].securityContext?.capabilities?.drop?.includes('ALL'));

    const bifrost = docs.find((d) => d.kind === 'Deployment' && d.metadata.name.endsWith('-bifrost'));
    assert.equal(bifrost.spec.template.spec.containers[0].envFrom, undefined);
    const bifrostEnvNames = bifrost.spec.template.spec.containers[0].env.map((e) => e.name);
    assert.deepEqual(bifrostEnvNames, ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'GEMINI_API_KEY', 'OLLAMA_URL']);
    assert.equal(bifrost.spec.template.spec.containers[0].securityContext?.allowPrivilegeEscalation, false);

    const pgadmin = docs.find((d) => d.kind === 'Deployment' && d.metadata.name.endsWith('-pgadmin'));
    const serverMode = pgadmin.spec.template.spec.containers[0].env.find((e) => e.name === 'PGADMIN_CONFIG_SERVER_MODE');
    assert.equal(serverMode?.value, 'True');
    assert.equal(pgadmin.spec.template.spec.containers[0].securityContext?.allowPrivilegeEscalation, false);
  });

  it('[SEC-M49] Suricata and Zeek use direct binary args, strict capabilities, and NetworkPolicies', () => {
    for (const [name, expectedCmd] of [['suricata', ['suricata']], ['zeek', ['zeek']]]) {
      const chart = chartPath(name);
      helmLint(chart);
      const { docs } = helmTemplateDocs(name, chart);
      const ds = docs.find((d) => d.kind === 'DaemonSet');
      assert.equal(ds.spec.template.spec.automountServiceAccountToken, false);
      const main = ds.spec.template.spec.containers[0];
      assert.deepEqual(main.command, expectedCmd);
      assert.equal(main.securityContext?.allowPrivilegeEscalation, false);
      assert.deepEqual(main.securityContext?.capabilities?.drop, ['ALL']);
      assert.deepEqual(main.securityContext?.capabilities?.add, ['NET_ADMIN', 'NET_RAW']);

      const np = docs.find((d) => d.kind === 'NetworkPolicy');
      assert.ok(np);
      assert.deepEqual(np.spec.policyTypes, ['Ingress', 'Egress']);

      assert.throws(
        () => helmTemplateDocs(name, chart, ['--set', 'interface=eth0;id']),
        /invalid network interface name/
      );
    }

    assert.throws(
      () => helmTemplateDocs('suricata', chartPath('suricata'), ['--set', 'runMode=workers;id']),
      /invalid suricata runMode/
    );
  });

  it('[SEC-M49] Falco and BloodHound pin tags, enforce securityContext & NetworkPolicies, and disable unauthenticated Falco UI Ingress', () => {
    const falcoChart = chartPath('falco');
    helmLint(falcoChart);
    const { raw: falcoRaw, docs: falcoDocs } = helmTemplateDocs('falco', falcoChart);
    assert.equal(falcoDocs.some((d) => d.kind === 'Ingress'), false, 'Falco UI Ingress must be disabled by default');
    assert.equal(/:latest\b/.test(falcoRaw), false, 'Falco rendered images must not use :latest');

    const falcoDs = falcoDocs.find((d) => d.kind === 'DaemonSet');
    const falcoC = falcoDs.spec.template.spec.containers[0];
    assert.notEqual(falcoC.securityContext?.privileged, true);
    assert.equal(falcoC.securityContext?.allowPrivilegeEscalation, false);
    assert.ok(falcoC.securityContext?.capabilities?.drop?.includes('ALL'));

    const sidekick = falcoDocs.find((d) => d.kind === 'Deployment');
    assert.equal(sidekick.spec.template.spec.automountServiceAccountToken, false);
    for (const c of sidekick.spec.template.spec.containers) {
      assert.equal(c.securityContext?.allowPrivilegeEscalation, false);
      assert.ok(c.securityContext?.capabilities?.drop?.includes('ALL'));
    }
    const falcoNps = falcoDocs.filter((d) => d.kind === 'NetworkPolicy');
    assert.equal(falcoNps.length, 2);
    assert.ok(JSON.stringify(falcoNps).includes('169.254.169.254/32'));

    const bhChart = chartPath('bloodhound');
    helmLint(bhChart);
    assert.throws(
      () => helmTemplateDocs('bloodhound', bhChart),
      /postgres\.password or existingSecret is required/
    );

    const { raw: bhRaw, docs: bhDocs } = helmTemplateDocs('bloodhound', bhChart, ['--set', 'existingSecret=bh-sec']);
    assert.equal(/:latest\b/.test(bhRaw), false, 'BloodHound rendered images must not use :latest');
    for (const w of bhDocs.filter((d) => d.kind === 'Deployment' || d.kind === 'StatefulSet')) {
      assert.equal(w.spec.template.spec.automountServiceAccountToken, false);
      for (const c of w.spec.template.spec.containers) {
        assert.equal(c.securityContext?.allowPrivilegeEscalation, false);
        assert.ok(c.securityContext?.capabilities?.drop?.includes('ALL'));
      }
    }
    const bhNps = bhDocs.filter((d) => d.kind === 'NetworkPolicy');
    assert.equal(bhNps.length, 3);
  });
});
