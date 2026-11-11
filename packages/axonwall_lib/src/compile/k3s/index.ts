import type { DesiredState, K3sConfig } from '../../schemas/index.js';
import { isValidDevice } from '../../util/index.js';

export interface CompiledK3s {
  k3sConfigYaml: string;
  openEbsManifestYaml: string;
  workloadsManifestYaml: string;
  ciliumManifestYaml?: string;
  serviceLbManifestYaml?: string;
}

export function compileK3s(state: DesiredState, joinToken?: string): CompiledK3s {
  const k3s: K3sConfig = state.k3s ?? {
    enabled: false,
    clusterCidr: '10.42.0.0/16',
    serviceCidr: '10.43.0.0/16',
    nodeIpInterface: 'lan',
    cniPlugin: 'flannel',
    flannelBackend: 'wireguard-native',
    ciliumKubeProxyReplacement: true,
    ciliumHubbleEnabled: true,
    haTopology: 'embedded-etcd',
    disableTraefik: false,
    autoJoinHaPeer: true,
    enableUserNamespaces: true,
    bpfTokenProfiles: [],
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
  for (const iface of state.interfaces ?? []) {
    const cleanIp = (iface.ipv4Address || (iface as { address?: string }).address || '').split('/')[0];
    if (cleanIp) tlsSans.add(cleanIp);
  }
  for (const vip of state.virtualIps ?? []) {
    const cleanIp = vip.ip.split('/')[0];
    if (cleanIp) tlsSans.add(cleanIp);
  }
  for (const vi of state.ha?.vrrpInstances ?? []) {
    for (const rawVip of vi.virtualIps ?? []) {
      const cleanIp = rawVip.split('/')[0];
      if (cleanIp) tlsSans.add(cleanIp);
    }
  }

  const useCilium = k3s.cniPlugin === 'cilium-ebpf';
  const effectiveFlannel = useCilium ? 'none' : k3s.flannelBackend;

  const configLines: string[] = [
    '# Axonwall Auto-Generated K3s Control Plane Configuration',
    `write-kubeconfig-mode: "0640"`,
    `write-kubeconfig-group: "axonwall-api"`,
    `cluster-cidr: "${k3s.clusterCidr}"`,
    `service-cidr: "${k3s.serviceCidr}"`,
    `flannel-backend: "${effectiveFlannel}"`,
  ];

  if (useCilium) {
    configLines.push('disable-network-policy: true');
    if (k3s.ciliumKubeProxyReplacement !== false) {
      configLines.push('disable-kube-proxy: true');
    }
  }

  // Resolve flannel-iface / node-ip: prefer the configured nodeIpInterface ('lan' by default),
  // falling back to the first enabled host interface on 1-NIC or Host-Mode nodes
  // where only 'wan' (eth0) exists.
  const ifaceObj =
    state.interfaces.find((i) => i.enabled && i.name === k3s.nodeIpInterface && isValidDevice(i.device)) ||
    state.interfaces.find((i) => i.name === k3s.nodeIpInterface && isValidDevice(i.device)) ||
    state.interfaces.find((i) => i.enabled && isValidDevice(i.device));
  let primaryNodeIp = '';
  if (isValidDevice(ifaceObj?.device)) {
    if (!useCilium) {
      configLines.push(`flannel-iface: "${ifaceObj!.device}"`);
    }
    const nodeIp = (ifaceObj!.ipv4Address || (ifaceObj as { address?: string }).address || '').split('/')[0];
    if (nodeIp) {
      primaryNodeIp = nodeIp;
      configLines.push(`node-ip: "${nodeIp}"`);
    }
  }

  const haTopology = k3s.haTopology || 'embedded-etcd';
  if (haTopology === 'external-datastore' && k3s.externalDatastoreEndpoint) {
    const safeDs = String(k3s.externalDatastoreEndpoint).replace(/[\r\n"]/g, '').trim();
    configLines.push(`datastore-endpoint: "${safeDs}"`);
  } else if (isSecondaryJoin && effectivePeer) {
    const formattedPeer = effectivePeer.includes(':') && !effectivePeer.startsWith('[')
      ? `[${effectivePeer}]`
      : effectivePeer;
    configLines.push(`server: "https://${formattedPeer}:6443"`);
    if (joinToken) {
      configLines.push(`token: "${joinToken}"`);
    } else {
      configLines.push(`token-file: "/var/lib/axonwall/k3s-join.token"`);
    }
  } else if (haTopology !== 'single-server-ha-agent') {
    configLines.push('cluster-init: true');
  }

  const disabledComponents: string[] = [];
  if (k3s.disableTraefik) {
    disabledComponents.push('traefik');
  }
  if ((k3s.serviceLbPools ?? []).length > 0 || useCilium) {
    disabledComponents.push('servicelb');
  }
  if (disabledComponents.length > 0) {
    configLines.push('disable:');
    for (const comp of disabledComponents) {
      configLines.push(`  - ${comp}`);
    }
  }

  if (k3s.etcdSnapshots?.enabled && haTopology === 'embedded-etcd') {
    const snapCron = String(k3s.etcdSnapshots.scheduleCron || '0 */6 * * *').replace(/[\r\n"]/g, '').trim();
    const snapDir = String(k3s.etcdSnapshots.snapshotDir || '/var/lib/rancher/k3s/server/db/snapshots')
      .replace(/[\r\n"]/g, '')
      .trim();
    configLines.push(`etcd-snapshot-schedule-cron: "${snapCron}"`);
    configLines.push(`etcd-snapshot-retention: ${k3s.etcdSnapshots.retention ?? 14}`);
    configLines.push(`etcd-snapshot-dir: "${snapDir}"`);
    if (k3s.etcdSnapshots.s3Enabled && k3s.etcdSnapshots.s3Bucket) {
      configLines.push('etcd-s3: true');
      configLines.push(`etcd-s3-bucket: "${String(k3s.etcdSnapshots.s3Bucket).replace(/[\r\n"]/g, '').trim()}"`);
      configLines.push(`etcd-s3-region: "${String(k3s.etcdSnapshots.s3Region || 'us-east-1').replace(/[\r\n"]/g, '').trim()}"`);
      if (k3s.etcdSnapshots.s3Endpoint) {
        configLines.push(`etcd-s3-endpoint: "${String(k3s.etcdSnapshots.s3Endpoint).replace(/[\r\n"]/g, '').trim()}"`);
      }
    }
  }

  if (k3s.enableUserNamespaces || (k3s.bpfTokenProfiles && k3s.bpfTokenProfiles.some((p) => p.enabled))) {
    configLines.push('kubelet-arg:');
    configLines.push('  - "feature-gates=UserNamespacesSupport=true"');
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

    if (wl.bpfTokenProfileId) {
      const safeProfId = sanitizeK8sId(wl.bpfTokenProfileId);
      deployLines.splice(
        deployLines.indexOf('      containers:'),
        0,
        '      hostUsers: false',
        '      securityContext:',
        '        seccompProfile:',
        '          type: RuntimeDefault',
      );
      deployLines.push(
        '          env:',
        '            - name: LIBBPF_BPF_TOKEN_PATH',
        '              value: /sys/fs/bpf',
        '          securityContext:',
        '            allowPrivilegeEscalation: false',
        '            capabilities:',
        '              drop: ["ALL"]',
        '              add: ["BPF", "NET_ADMIN"]',
      );
      if (wl.storageClass === 'none') {
        deployLines.push(
          '          volumeMounts:',
          '            - name: bpf-token-bpffs',
          '              mountPath: /sys/fs/bpf',
          '              readOnly: true',
          '      volumes:',
          '        - name: bpf-token-bpffs',
          '          hostPath:',
          `            path: /run/axonwall/bpf-tokens/${safeProfId}`,
          '            type: Directory',
        );
      }
    }

    workloadDocs.push(deployLines.join('\n'));

    // Service for every enabled workload
    const svcType = wl.serviceType || 'ClusterIP';
    workloadDocs.push(
      [
        'apiVersion: v1',
        'kind: Service',
        'metadata:',
        `  name: ${safeName}`,
        `  namespace: ${ns}`,
        'spec:',
        `  type: ${svcType}`,
        '  selector:',
        `    app: ${safeName}`,
        '  ports:',
        `    - name: http`,
        '      protocol: TCP',
        `      port: ${wl.port}`,
        `      targetPort: ${wl.port}`,
      ].join('\n'),
    );

    if (wl.ingressHostname) {
      const safeHost = sanitizeScalar(wl.ingressHostname).replace(/[^a-zA-Z0-9.-]/g, '');
      if (safeHost) {
        workloadDocs.push(
          [
            'apiVersion: networking.k8s.io/v1',
            'kind: Ingress',
            'metadata:',
            `  name: ${safeName}-ingress`,
            `  namespace: ${ns}`,
            '  annotations:',
            '    axonwall.io/auto-unbound-dns: "true"',
            'spec:',
            '  rules:',
            `    - host: ${safeHost}`,
            '      http:',
            '        paths:',
            '          - path: /',
            '            pathType: Prefix',
            '            backend:',
            '              service:',
            `                name: ${safeName}`,
            '                port:',
            `                  number: ${wl.port}`,
          ].join('\n'),
        );
      }
    }
  }

  let ciliumManifestYaml: string | undefined;
  if (useCilium) {
    const k8sHost = primaryNodeIp || '127.0.0.1';
    ciliumManifestYaml = [
      '# Axonwall Auto-Generated Cilium eBPF CNI + Kube-Proxy Replacement Manifest',
      'apiVersion: helm.cattle.io/v1',
      'kind: HelmChart',
      'metadata:',
      '  name: cilium',
      '  namespace: kube-system',
      'spec:',
      '  repo: https://helm.cilium.io/',
      '  chart: cilium',
      '  targetNamespace: kube-system',
      '  valuesContent: |-',
      `    kubeProxyReplacement: "${k3s.ciliumKubeProxyReplacement !== false ? 'true' : 'false'}"`,
      `    k8sServiceHost: "${k8sHost}"`,
      '    k8sServicePort: 6443',
      '    bpf:',
      '      masquerade: true',
      '    ipam:',
      '      operator:',
      `        clusterPoolIPv4PodCIDRList: ["${k3s.clusterCidr}"]`,
      '    l2announcements:',
      '      enabled: true',
      '    bgpControlPlane:',
      `      enabled: ${Boolean(state.frr?.bgp?.enabled)}`,
      '    hubble:',
      `      enabled: ${k3s.ciliumHubbleEnabled !== false}`,
      '      relay:',
      `        enabled: ${k3s.ciliumHubbleEnabled !== false}`,
      '',
    ].join('\n');
  }

  let serviceLbManifestYaml: string | undefined;
  const lbPools = k3s.serviceLbPools ?? [];
  if (lbPools.length > 0) {
    const lbDocs: string[] = ['# Axonwall Bare-Metal LoadBalancer IP Pools (Cilium LB-IPAM + FRR BGP / L2 ARP)'];
    for (const pool of lbPools) {
      const safePoolName = sanitizeK8sId(pool.name);
      lbDocs.push(
        [
          'apiVersion: cilium.io/v2alpha1',
          'kind: CiliumLoadBalancerIPPool',
          'metadata:',
          `  name: ${safePoolName}`,
          'spec:',
          '  blocks:',
          `    - cidr: "${sanitizeScalar(pool.cidr)}"`,
          `  disabled: ${!pool.autoAssign}`,
        ].join('\n'),
      );
      if (pool.mode === 'l2-arp' || pool.mode === 'both') {
        lbDocs.push(
          [
            'apiVersion: cilium.io/v2alpha1',
            'kind: CiliumL2AnnouncementPolicy',
            'metadata:',
            `  name: ${safePoolName}-l2`,
            'spec:',
            '  externalIPs: true',
            '  loadBalancerIPs: true',
          ].join('\n'),
        );
      }
      if ((pool.mode === 'bgp' || pool.mode === 'both') && state.frr?.bgp?.enabled) {
        lbDocs.push(
          [
            'apiVersion: cilium.io/v2alpha1',
            'kind: CiliumBGPPeeringPolicy',
            'metadata:',
            `  name: ${safePoolName}-bgp`,
            'spec:',
            '  virtualRouters:',
            `    - localASN: ${state.frr.bgp.asNumber}`,
            '      exportPodCIDR: true',
            '      serviceSelector:',
            '        matchExpressions:',
            '          - key: somekey',
            '            operator: NotIn',
            '            values: ["never-used-value"]',
            '      neighbors:',
            `        - peerAddress: "${primaryNodeIp || '127.0.0.1'}/32"`,
            `          peerASN: ${state.frr.bgp.asNumber}`,
          ].join('\n'),
        );
      }
    }
    serviceLbManifestYaml = lbDocs.join('\n---\n') + '\n';
  }

  return {
    k3sConfigYaml: configLines.join('\n'),
    openEbsManifestYaml,
    workloadsManifestYaml: workloadDocs.join('\n---\n'),
    ...(ciliumManifestYaml ? { ciliumManifestYaml } : {}),
    ...(serviceLbManifestYaml ? { serviceLbManifestYaml } : {}),
  };
}
