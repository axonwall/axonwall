import { execa } from 'execa';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs/promises';
import { BaseModule } from '../base.js';
import { execStream } from '../../utils/exec.js';
import { applyK8sTlsSecret } from '../../engine/certs.js';
import { ensureNamespace, ensureGeneratedK8sSecret, generateStrongSecret, getClusterContextArgs, getHelmContextArgs, getKubeExecutionEnv } from '../../engine/k8s.js';
import { assertDnsLabel } from '../../engine/config.js';
import { resolveChartValuesArgs, cleanupHelmTempValues } from '../../engine/helm.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export class OpenVASModule extends BaseModule {
  constructor() {
    super({
      id: 'openvas',
      name: 'OpenVAS / Greenbone Community Edition',
      description: 'Greenbone Vulnerability Management (GVM) Suite with OpenVAS Scanner, GSAD Web UI & GMP API',
      category: 'scanner',
      version: '24.10.0',
      dependencies: [],
      defaultEnabled: false
    });
    this.namespace = 'openvas';
    this.tlsSecretName = 'openvas-tls';
  }

  /**
   * Install OpenVAS / Greenbone Community Edition into target namespace
   */
  async install({
    domain = 'vigilante.local',
    certPath = null,
    keyPath = null,
    clusterName = 'vigilante-dev',
    namespace = null,
    onLog = null,
    options = {}
  } = {}) {
    const targetNamespace = namespace || options?.namespace || this.namespace;
    const targetTlsSecret = `${targetNamespace}-tls`;
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'openvas';
    const releaseName = isStandardNs ? 'openvas' : `${targetNamespace}-openvas`;
    const ingressHost = isStandardNs ? `openvas.${domain}` : `${targetNamespace}-openvas.${domain}`;

    if (onLog) onLog(`[openvas] Preparing namespace '${targetNamespace}' on cluster '${clusterName}'...`);

    // 1. Ensure target namespace exists safely
    await ensureNamespace(targetNamespace, { onLog });

    // 2. Inject TLS secret for Ingress
    if (certPath && keyPath) {
      if (onLog) onLog(`[openvas] Injecting mkcert TLS secret '${targetTlsSecret}' into namespace '${targetNamespace}'...`);
      await applyK8sTlsSecret({
        namespace: targetNamespace,
        secretName: targetTlsSecret,
        certPath,
        keyPath
      });
    }

    // 3. Resolve Helm Chart Values
    if (onLog) onLog(`[openvas] Deploying Greenbone Community Edition '${releaseName}' (Ingress: https://${ingressHost})...`);
    const openvasChartPath = path.join(__dirname, 'charts', 'openvas');
    const openvasDefaultValues = path.join(__dirname, 'values', 'openvas.yaml');
    const kubeEnv = getKubeExecutionEnv();
    const helmCtxArgs = await getHelmContextArgs(clusterName);

    const openvasValuesArgs = await resolveChartValuesArgs({
      moduleId: this.id,
      chartName: 'openvas',
      defaultValuesPath: openvasDefaultValues,
      customValuesPath: options?.customValuesPath || options?.values,
      customValuesDir: options?.customValuesDir || options?.valuesDir,
      domain,
      tlsSecretName: targetTlsSecret,
      namespace: targetNamespace,
      clusterName,
      onLog
    });

    try {
      const secretName = `${releaseName}-admin`;
      await ensureGeneratedK8sSecret({
        namespace: targetNamespace,
        secretName,
        clusterName,
        keys: {
          username: 'admin',
          password: () => generateStrongSecret(),
          postgresPassword: () => generateStrongSecret()
        }
      });

      const helmArgs = [
        'upgrade', '--install', releaseName, openvasChartPath,
        ...helmCtxArgs,
        '--namespace', targetNamespace,
        '--timeout', options?.timeout || '10m',
        '--set', `existingSecret=${secretName}`,
        ...openvasValuesArgs
      ];

      await execStream('helm', helmArgs, { onLog, env: kubeEnv });
    } finally {
      await cleanupHelmTempValues(openvasValuesArgs);
    }

    if (onLog) {
      onLog(`[openvas] Successfully deployed OpenVAS / Greenbone in namespace '${targetNamespace}'! Ingress: https://${ingressHost}`);
      try {
        const creds = await this.getCredentials({ clusterName, namespace: targetNamespace });
        if (creds) {
          onLog(`[openvas] Greenbone Security Assistant login: ${creds.username} / [stored in secret ${releaseName}-admin]`);
        }
      } catch {
        // Ignore if credentials secret is not yet readable
      }
    }
  }

  /**
   * Uninstall OpenVAS and optionally clean up namespace
   */
  async uninstall({ clusterName = 'vigilante-dev', namespace = null, onLog = null, deleteNamespace = false } = {}) {
    const targetNamespace = namespace || this.namespace;
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'openvas';
    const releaseName = isStandardNs ? 'openvas' : `${targetNamespace}-openvas`;
    const kubeEnv = getKubeExecutionEnv();
    const helmCtxArgs = await getHelmContextArgs(clusterName);
    const ctxArgs = await getClusterContextArgs(clusterName);

    if (onLog) onLog(`[openvas] Uninstalling Greenbone Community Edition from namespace '${targetNamespace}'...`);
    try {
      await execa('helm', ['uninstall', releaseName, '-n', targetNamespace, ...helmCtxArgs], { env: kubeEnv });
    } catch {
      // Ignore if already uninstalled
    }

    if (deleteNamespace && targetNamespace !== 'default' && targetNamespace !== 'kube-system') {
      if (onLog) onLog(`[openvas] Deleting namespace '${targetNamespace}'...`);
      try {
        await execa('kubectl', ['delete', 'namespace', targetNamespace, '--timeout=60s', ...ctxArgs], { env: kubeEnv });
      } catch {
        // Ignore if already deleted
      }
    }
  }

  /**
   * Check status of OpenVAS components
   */
  async status({ domain = 'vigilante.local', clusterName = 'vigilante-dev', namespace = null } = {}) {
    const targetNamespace = assertDnsLabel(namespace || this.namespace, 'namespace');

    try {
      const kubeEnv = getKubeExecutionEnv();
      const ctxArgs = await getClusterContextArgs(clusterName);
      const { stdout: podsJson } = await execa('kubectl', [
        'get', 'pods',
        '-n', targetNamespace,
        '-l', 'app.kubernetes.io/name=openvas',
        ...ctxArgs,
        '--request-timeout=3s',
        '-o', 'json'
      ], { env: kubeEnv });
      const parsed = JSON.parse(podsJson);
      const pods = (parsed.items || []).map(p => ({
        name: p.metadata.name,
        namespace: p.metadata.namespace || targetNamespace,
        phase: p.status.phase,
        ready: p.status.containerStatuses?.every(c => c.ready) || false,
        restarts: p.status.containerStatuses?.reduce((acc, c) => acc + c.restartCount, 0) || 0
      }));

      const isInstalled = pods.length > 0;
      const allReady = isInstalled && pods.every(p => p.ready || p.phase === 'Succeeded');

      return {
        id: this.id,
        name: this.name,
        namespace: targetNamespace,
        installed: isInstalled,
        status: allReady ? 'Ready' : isInstalled ? 'Deploying / Degraded' : 'Not Installed',
        pods,
        endpoints: await this.getEndpoints({ domain, namespace: targetNamespace })
      };
    } catch {
      return {
        id: this.id,
        name: this.name,
        namespace: targetNamespace,
        installed: false,
        status: 'Not Installed',
        pods: [],
        endpoints: []
      };
    }
  }

  /**
   * Retrieve administrative credentials from the OpenVAS secret
   */
  async getCredentials({ clusterName = 'vigilante-dev', namespace = null } = {}) {
    const targetNamespace = assertDnsLabel(namespace || this.namespace, 'namespace');
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'openvas';
    const secretName = isStandardNs ? 'openvas-admin' : `${targetNamespace}-openvas-admin`;

    try {
      const kubeEnv = getKubeExecutionEnv();
      const ctxArgs = await getClusterContextArgs(clusterName);
      const { stdout: b64Data } = await execa('kubectl', [
        'get', 'secret', secretName,
        '-n', targetNamespace,
        ...ctxArgs,
        '--request-timeout=5s',
        '-o', 'jsonpath={.data.username}|{.data.password}'
      ], { env: kubeEnv });

      if (!b64Data || !b64Data.includes('|')) return null;
      const [b64User, b64Pass] = b64Data.split('|');
      return {
        username: Buffer.from(b64User, 'base64').toString('utf8'),
        password: Buffer.from(b64Pass, 'base64').toString('utf8')
      };
    } catch {
      return null;
    }
  }

  /**
   * List endpoints for OpenVAS / Greenbone Community Edition
   */
  async getEndpoints({ domain = 'vigilante.local', namespace = null } = {}) {
    const targetNamespace = namespace || this.namespace;
    const isStandardNs = targetNamespace === 'default' || targetNamespace === 'openvas';
    const webUrl = isStandardNs ? `https://openvas.${domain}` : `https://${targetNamespace}-openvas.${domain}`;
    const gvmUrl = isStandardNs ? `https://gvm.${domain}` : `https://${targetNamespace}-gvm.${domain}`;

    return [
      {
        name: `Greenbone Security Assistant (GSAD, ${targetNamespace})`,
        url: webUrl,
        namespace: targetNamespace,
        description: 'Greenbone web interface for vulnerability audits, scan management & CVE reports'
      },
      {
        name: `GVM Ingress Alias (${targetNamespace})`,
        url: gvmUrl,
        namespace: targetNamespace,
        description: 'Direct alias for Greenbone Vulnerability Management Web UI'
      },
      {
        name: `OpenVAS Daemon API (Internal, ${targetNamespace})`,
        url: `http://openvas-service.${targetNamespace}.svc.cluster.local:81`,
        namespace: targetNamespace,
        description: 'OpenVAS REST API daemon for vulnerability checks and scanner control'
      },
      {
        name: `GSAD Web Service (Internal, ${targetNamespace})`,
        url: `http://openvas-service.${targetNamespace}.svc.cluster.local:9392`,
        namespace: targetNamespace,
        description: 'Internal HTTP service for GSAD web console'
      }
    ];
  }
}
