import type { DesiredState, K3sConfig } from '../../schemas/index.js';

export interface CompiledK3s {
  k3sConfigYaml: string;
  openEbsManifestYaml: string;
  workloadsManifestYaml: string;
}

export function compileK3s(state: DesiredState, joinToken?: string): CompiledK3s {
  const k3s: K3sConfig = state.k3s ?? {
    enabled: false,
    clusterCidr: '10.42.0.0/16',
    serviceCidr: '10.43.0.0/16',
    nodeIpInterface: 'lan',
    flannelBackend: 'wireguard-native',
    disableTraefik: false,
    autoJoinHaPeer: true,
    openEbs: {
      enabled: true,
      zfsLocalPvEnabled: true,
      zfsLocalPvPool: 'tank',
      replicatedStorageEnabled: true,
      defaultReplicaCount: 2,
      replicatedBackingPool: 'tank/openebs-replicated',
    },
    workloads: [],
  };

  const effectiveRole = state.ha?.role || state.ha?.nodeRole || 'master';
  const effectivePeer = state.ha?.peerIp || state.ha?.peerAddress || '';

  const isSecondaryJoin =
    Boolean(state.ha?.enabled) &&
    effectiveRole === 'backup' &&
    Boolean(effectivePeer) &&
    k3s.autoJoinHaPeer !== false;

  const tlsSans = new Set<string>(['127.0.0.1', 'localhost']);
  if (effectivePeer) {
    tlsSans.add(effectivePeer);
  }
  for (const vip of state.virtualIps ?? []) {
    const cleanIp = vip.ip.split('/')[0];
    if (cleanIp) tlsSans.add(cleanIp);
  }

  const configLines: string[] = [
    '# Axonwall Auto-Generated K3s Control Plane Configuration',
    `write-kubeconfig-mode: "0640"`,
    `cluster-cidr: "${k3s.clusterCidr}"`,
    `service-cidr: "${k3s.serviceCidr}"`,
    `flannel-backend: "${k3s.flannelBackend}"`,
  ];

  const ifaceObj = state.interfaces.find((i) => i.name === k3s.nodeIpInterface);
  if (ifaceObj?.device) {
    configLines.push(`flannel-iface: "${ifaceObj.device}"`);
  }

  if (isSecondaryJoin && effectivePeer) {
    const formattedPeer = effectivePeer.includes(':') && !effectivePeer.startsWith('[')
      ? `[${effectivePeer}]`
      : effectivePeer;
    configLines.push(`server: "https://${formattedPeer}:6443"`);
    if (joinToken) {
      configLines.push(`token: "${joinToken}"`);
    } else {
      configLines.push(`token-file: "/var/lib/axonwall/k3s-join.token"`);
    }
  } else {
    configLines.push('cluster-init: true');
  }

  if (k3s.disableTraefik) {
    configLines.push('disable:');
    configLines.push('  - traefik');
  }

  configLines.push('tls-san:');
  for (const san of tlsSans) {
    configLines.push(`  - "${san}"`);
  }
  configLines.push('');

  const zfsPool = k3s.openEbs?.zfsLocalPvPool || 'tank';
  const replicaCount = state.ha?.enabled ? (k3s.openEbs?.defaultReplicaCount ?? 2) : 1;

  const openEbsManifestYaml = [
    '# Axonwall Auto-Generated OpenEBS StorageClasses (ZFS-LocalPV + Replicated HA)',
    'apiVersion: v1',
    'kind: Namespace',
    'metadata:',
    '  name: openebs',
    '---',
    'apiVersion: storage.k8s.io/v1',
    'kind: StorageClass',
    'metadata:',
    '  name: axonwall-zfs-local',
    '  annotations:',
    `    storageclass.kubernetes.io/is-default-class: "${k3s.openEbs?.replicatedStorageEnabled ? 'false' : 'true'}"`,
    'provisioner: zfs.csi.openebs.io',
    'allowVolumeExpansion: true',
    'parameters:',
    '  fstype: "zfs"',
    '  compression: "lz4"',
    '  dedup: "off"',
    '  recordsize: "128k"',
    `  poolname: "${zfsPool}"`,
    'reclaimPolicy: Retain',
    'volumeBindingMode: WaitForFirstConsumer',
    '---',
    'apiVersion: storage.k8s.io/v1',
    'kind: StorageClass',
    'metadata:',
    '  name: axonwall-replicated-ha',
    '  annotations:',
    `    storageclass.kubernetes.io/is-default-class: "${k3s.openEbs?.replicatedStorageEnabled ? 'true' : 'false'}"`,
    'provisioner: io.openebs.csi-mayastor',
    'allowVolumeExpansion: true',
    'parameters:',
    '  protocol: "nvmf"',
    '  ioTimeout: "30"',
    `  repl: "${replicaCount}"`,
    `  backingZfsPool: "${k3s.openEbs?.replicatedBackingPool || `${zfsPool}/openebs-replicated`}"`,
    'reclaimPolicy: Retain',
    'volumeBindingMode: Immediate',
    '',
  ].join('\n');

  const sanitizeK8sId = (v: string) => v.replace(/[^a-z0-9-.]/gi, '-').toLowerCase();
  const sanitizeScalar = (v: string) => v.replace(/[\r\n]/g, '').trim();

  const workloadDocs: string[] = [];
  for (const wl of k3s.workloads ?? []) {
    if (!wl.enabled) continue;
    const safeName = sanitizeK8sId(wl.name);
    const ns = sanitizeK8sId(wl.namespace || 'default');
    const safeSc = sanitizeK8sId(wl.storageClass);
    const safeImage = sanitizeScalar(wl.image);
    const safeMount = sanitizeScalar(wl.mountPath);

    if (wl.storageClass !== 'none') {
      workloadDocs.push(
        [
          'apiVersion: v1',
          'kind: PersistentVolumeClaim',
          'metadata:',
          `  name: ${safeName}-pvc`,
          `  namespace: ${ns}`,
          'spec:',
          '  accessModes:',
          '    - ReadWriteOnce',
          `  storageClassName: ${safeSc}`,
          '  resources:',
          '    requests:',
          `      storage: ${wl.storageSizeGb}Gi`,
        ].join('\n'),
      );
    }

    const deployLines = [
      'apiVersion: apps/v1',
      'kind: Deployment',
      'metadata:',
      `  name: ${safeName}`,
      `  namespace: ${ns}`,
      'spec:',
      `  replicas: ${wl.replicas}`,
      '  selector:',
      '    matchLabels:',
      `      app: ${safeName}`,
      '  template:',
      '    metadata:',
      '      labels:',
      `        app: ${safeName}`,
      '    spec:',
      '      containers:',
      `        - name: ${safeName}`,
      `          image: ${safeImage}`,
      '          ports:',
      `            - containerPort: ${wl.port}`,
    ];

    if (wl.storageClass !== 'none') {
      deployLines.push(
        '          volumeMounts:',
        `            - name: data`,
        `              mountPath: ${safeMount}`,
        '      volumes:',
        '        - name: data',
        '          persistentVolumeClaim:',
        `            claimName: ${safeName}-pvc`,
      );
    }

    workloadDocs.push(deployLines.join('\n'));
  }

  return {
    k3sConfigYaml: configLines.join('\n'),
    openEbsManifestYaml,
    workloadsManifestYaml: workloadDocs.join('\n---\n'),
  };
}
