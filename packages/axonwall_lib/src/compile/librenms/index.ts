import {
  LibreNmsConfigSchema,
  type DesiredState,
  type LibreNmsConfig,
} from '../../schemas/index.js';
import { isPluginEnabled } from '../../plugins/index.js';
import {
  buildUnboundLocalDataOverride,
  deriveBaseDn,
  indentMultiline,
  resolveApplianceLanIp,
  rewritePodLdapUrl,
  yamlStr,
} from '../k3s/helpers.js';

export interface LibreNmsEnrollmentTarget {
  id: string;
  hostname: string;
  displayName: string;
  source: 'local' | 'ha-peer' | 'fleet' | 'topology-peer';
  snmpVersion: 'v2c' | 'v3';
  port: number;
  sysRole: string;
}

export interface LibreNmsEnrollmentPlan {
  snmpEnabledOnLocal: boolean;
  targets: LibreNmsEnrollmentTarget[];
  discoverySubnets: Array<{ cidr: string; label: string }>;
  summary: {
    targetsCount: number;
    subnetsCount: number;
  };
}

export interface CompiledLibreNmsBundle {
  enabled: boolean;
  k3sDependencyMet: boolean;
  mode: 'k3s' | 'external';
  config: LibreNmsConfig;
  namespace: string;
  domain: string;
  endpointUrl: string;
  internalServiceUrl: string;
  lanIp: string;
  baseDn: string;
  bindDn: string;
  podLdapUrl: string;
  ldapConfigPhp: string;
  discoveryConfigPhp: string;
  unboundOverrides: string;
  k3sManifestsYaml: string;
  enrollmentPlan: LibreNmsEnrollmentPlan;
}

function phpStr(v: unknown): string {
  const s = String(v ?? '').replace(/[\r\n\0]/g, '');
  return `'${s.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;
}

function extractHostFromUrl(rawUrl: string): string {
  try {
    const u = new URL(rawUrl);
    return u.hostname.trim();
  } catch {
    return rawUrl.trim().replace(/^https?:\/\//i, '').split(/[:/]/)[0]?.trim() || '';
  }
}

/**
 * Resolves the effective LibreNMS configuration merged with plugin enablement state.
 */
export function resolveLibreNmsConfig(state?: Partial<DesiredState> | null): LibreNmsConfig {
  const parsed = LibreNmsConfigSchema.parse(state?.librenms ?? {});
  const enabled = isPluginEnabled('librenms', state);
  return {
    ...parsed,
    enabled,
  };
}

/**
 * Builds the deterministic SNMP auto-enrollment & subnet discovery plan from DesiredState.
 */
export function buildLibreNmsEnrollmentPlan(state?: Partial<DesiredState> | null): LibreNmsEnrollmentPlan {
  const config = LibreNmsConfigSchema.parse(state?.librenms ?? {});
  const syncCfg = config.sync;
  const snmpVersion = config.snmpDefaults.version;
  const snmpPort = state?.snmp?.enabled ? state.snmp.listenPort : config.snmpDefaults.port;
  const lanIp = resolveApplianceLanIp(state);
  const localHost = state?.system?.hostname?.trim() || 'axonwall-fw';
  const targets: LibreNmsEnrollmentTarget[] = [];
  const seenHosts = new Set<string>();

  const pushTarget = (t: LibreNmsEnrollmentTarget) => {
    const key = t.hostname.trim().toLowerCase();
    if (!key || seenHosts.has(key)) return;
    seenHosts.add(key);
    targets.push(t);
  };

  if (syncCfg.autoEnrollAxonwallHosts && lanIp) {
    pushTarget({
      id: `local:${localHost}`,
      hostname: lanIp,
      displayName: localHost,
      source: 'local',
      snmpVersion,
      port: snmpPort,
      sysRole: 'axonwall-local',
    });

    if (state?.ha?.enabled && state.ha.peerIp?.trim()) {
      const peerIp = state.ha.peerIp.trim().split('/')[0]!.trim();
      if (peerIp) {
        pushTarget({
          id: `ha-peer:${peerIp}`,
          hostname: peerIp,
          displayName: `${localHost}-ha-peer`,
          source: 'ha-peer',
          snmpVersion,
          port: config.snmpDefaults.port,
          sysRole: `ha-${state.ha.role || 'peer'}`,
        });
      }
    }
  }

  if (syncCfg.autoEnrollFleetSatellites) {
    for (const sat of state?.fleet?.nodes ?? []) {
      const targetHost =
        (sat.wireguard?.tunnelIp || sat.ip || '').trim().split('/')[0]?.trim() || '';
      if (!targetHost || targetHost === '127.0.0.1') continue;
      pushTarget({
        id: `fleet:${sat.id}`,
        hostname: targetHost,
        displayName: sat.name || sat.id,
        source: 'fleet',
        snmpVersion,
        port: config.snmpDefaults.port,
        sysRole: sat.role || 'satellite',
      });
    }
  }

  if (syncCfg.autoEnrollTopologyPeers) {
    const rawTopo = (state as { topology?: { peers?: Array<{ id?: string; name?: string; role?: string; apiUrl?: string; enabled?: boolean }> } } | undefined)?.topology;
    for (const peer of rawTopo?.peers ?? []) {
      if (peer.enabled === false || !peer.apiUrl) continue;
      const host = extractHostFromUrl(peer.apiUrl);
      if (!host || host === '127.0.0.1' || host === 'localhost') continue;
      pushTarget({
        id: `peer:${peer.id || host}`,
        hostname: host,
        displayName: peer.name || peer.id || host,
        source: 'topology-peer',
        snmpVersion,
        port: config.snmpDefaults.port,
        sysRole: peer.role || 'peer',
      });
    }
  }

  const discoverySubnets = (config.discoverySubnets ?? [])
    .filter((s) => s.enabled && s.cidr.trim().length > 0)
    .map((s) => ({
      cidr: s.cidr.trim(),
      label: s.label.trim() || s.cidr.trim(),
    }));

  return {
    snmpEnabledOnLocal: Boolean(state?.snmp?.enabled),
    targets,
    discoverySubnets,
    summary: {
      targetsCount: targets.length,
      subnetsCount: discoverySubnets.length,
    },
  };
}

/**
 * Compiles the K3s manifests, OpenLDAP PHP config, discovery config, and Unbound DNS override for LibreNMS.
 */
export function compileLibreNmsBundle(state?: Partial<DesiredState> | null): CompiledLibreNmsBundle {
  const config = resolveLibreNmsConfig(state);
  const mode = config.mode;
  const k3sDependencyMet = isPluginEnabled('core-k3s', state);
  const enabled = config.enabled && (mode === 'external' || k3sDependencyMet);
  const deployK3s = enabled && mode === 'k3s';

  const lanIp = resolveApplianceLanIp(state);
  const namespace = config.namespace || 'librenms';
  const domain = config.domain || 'librenms.axonwall.local';
  const proto = config.ingressTls ? 'https' : 'http';
  const endpointUrl =
    mode === 'external' && config.externalUrl?.trim()
      ? config.externalUrl.trim().replace(/\/+$/, '')
      : config.externalUrl?.trim()
        ? config.externalUrl.trim().replace(/\/+$/, '')
        : `${proto}://${domain}`;
  const internalServiceUrl = `http://librenms.${namespace}.svc.cluster.local:${config.servicePort}`;

  const ldap = config.ldapAuth;
  const baseDn =
    ldap.baseDn?.trim() ||
    state?.identity?.baseDn?.trim() ||
    deriveBaseDn(state?.system?.domain || 'axonwall.local');
  const bindDn = ldap.bindDn?.trim() || `cn=svc-librenms,ou=services,${baseDn}`;
  const podLdapUrl = rewritePodLdapUrl(ldap.url || 'ldap://127.0.0.1:389', lanIp);
  let ldapPort = /^ldaps:\/\//i.test(podLdapUrl) ? 636 : 389;
  let ldapServerHost = lanIp;
  try {
    const parsedLdapUrl = new URL(podLdapUrl);
    const isLdaps = parsedLdapUrl.protocol.toLowerCase() === 'ldaps:';
    const parsedPort = parsedLdapUrl.port ? Number.parseInt(parsedLdapUrl.port, 10) : NaN;
    ldapPort = Number.isInteger(parsedPort) && parsedPort >= 1 && parsedPort <= 65535 ? parsedPort : isLdaps ? 636 : 389;
    const rawHost = parsedLdapUrl.hostname.replace(/^\[|\]$/g, '').trim();
    if (rawHost) {
      ldapServerHost = rawHost;
    }
  } catch {
    const stripped = podLdapUrl.replace(/^ldaps?:\/\//i, '').replace(/\/.*$/, '');
    ldapServerHost = stripped.split(':')[0] || lanIp;
  }

  const ldapConfigPhp = ldap.enabled
    ? [
        '<?php',
        '// Auto-generated by Axonwall LibreNMS Plugin Compiler (cn=svc-librenms)',
        "$config['auth_mechanism'] = 'ldap';",
        `$config['auth_ldap_server'] = ${phpStr(ldapServerHost)};`,
        `$config['auth_ldap_port'] = ${ldapPort};`,
        `$config['auth_ldap_prefix'] = 'uid=';`,
        `$config['auth_ldap_suffix'] = ${phpStr(`,ou=users,${baseDn}`)};`,
        `$config['auth_ldap_groupbase'] = ${phpStr(`ou=groups,${baseDn}`)};`,
        "$config['auth_ldap_groupmemberattr'] = 'memberUid';",
        "$config['auth_ldap_uid_attribute'] = 'uid';",
        "$config['auth_ldap_userdn'] = true;",
        `$config['auth_ldap_binddn'] = ${phpStr(bindDn)};`,
        "$config['auth_ldap_bindpassword'] = getenv('LIBRENMS_LDAP_BIND_PASSWORD') ?: '';",
        '$config[\'auth_ldap_groups\'] = [',
        ...(ldap.inheritApplianceAdmins
          ? ["    'axonwall-admin' => ['level' => 10],", "    'axonwall-operator' => ['level' => 5],", "    'axonwall-readonly' => ['level' => 1],"]
          : []),
        `    ${phpStr(ldap.adminGroup)} => ['level' => 10],`,
        `    ${phpStr(ldap.operatorGroup)} => ['level' => 5],`,
        `    ${phpStr(ldap.readonlyGroup)} => ['level' => 1],`,
        '];',
        '?>',
        '',
      ].join('\n')
    : "<?php\n// OpenLDAP authentication disabled in /etc/axonwall/services.yaml\n?>\n";

  const snmp = config.snmpDefaults;
  const enabledSubnets = (config.discoverySubnets ?? []).filter((s) => s.enabled && s.cidr.trim());
  const communityList = Array.from(
    new Set([snmp.community?.trim() || 'public', state?.snmp?.enabled ? state.snmp.community?.trim() : ''].filter(Boolean))
  );

  const discoveryConfigPhp = [
    '<?php',
    '// Auto-generated by Axonwall LibreNMS Discovery & SNMP Defaults',
    "$config['discovery_by_ip'] = true;",
    "$config['autodiscovery']['xdp'] = true;",
    "$config['autodiscovery']['ospf'] = true;",
    "$config['autodiscovery']['bgp'] = true;",
    "$config['autodiscovery']['snmpscan'] = true;",
    `$config['snmp']['community'] = [${communityList.map(phpStr).join(', ')}];`,
    ...(enabledSubnets.length > 0
      ? enabledSubnets.map((s) => `$config['nets'][] = ${phpStr(s.cidr.trim())};`)
      : ['// Configure management-VLAN CIDRs in services.yaml -> librenms.discoverySubnets']),
    '?>',
    '',
  ].join('\n');

  const unboundOverrides =
    deployK3s && config.unboundAutoDns && lanIp
      ? buildUnboundLocalDataOverride('Auto-generated by Axonwall LibreNMS Plugin Compiler', domain, lanIp)
      : '';

  const enrollmentPlan = buildLibreNmsEnrollmentPlan(state);

  let k3sManifestsYaml = '';
  if (deployK3s) {
    const tlsBlock = config.ingressTls
      ? [
          '  tls:',
          '    - hosts:',
          `        - ${yamlStr(domain)}`,
          '      secretName: librenms-tls',
        ].join('\n')
      : '';

    const ingressDoc = config.ingressEnabled
      ? [
          '---',
          'apiVersion: networking.k8s.io/v1',
          'kind: Ingress',
          'metadata:',
          '  name: librenms-ingress',
          `  namespace: ${yamlStr(namespace)}`,
          '  annotations:',
          '    traefik.ingress.kubernetes.io/router.entrypoints: web,websecure',
          'spec:',
          ...(tlsBlock ? [tlsBlock] : []),
          '  rules:',
          `    - host: ${yamlStr(domain)}`,
          '      http:',
          '        paths:',
          '          - path: /',
          '            pathType: Prefix',
          '            backend:',
          '              service:',
          '                name: librenms',
          '                port:',
          `                  number: ${config.servicePort}`,
        ].join('\n')
      : '';

    const sharedLibreNmsEnv = [
      '            - name: TZ',
      `              value: ${yamlStr(config.timezone || state?.system?.timezone || 'UTC')}`,
      '            - name: PUID',
      '              value: "1000"',
      '            - name: PGID',
      '              value: "1000"',
      '            - name: DB_HOST',
      '              value: "librenms-mariadb"',
      '            - name: DB_PORT',
      '              value: "3306"',
      '            - name: DB_NAME',
      '              value: "librenms"',
      '            - name: DB_USER',
      '              value: "librenms"',
      '            - name: DB_PASSWORD',
      '              valueFrom:',
      '                secretKeyRef:',
      '                  name: librenms-secrets',
      '                  key: db_password',
      '            - name: DB_TIMEOUT',
      '              value: "60"',
      '            - name: CACHE_DRIVER',
      '              value: "redis"',
      '            - name: SESSION_DRIVER',
      '              value: "redis"',
      '            - name: REDIS_HOST',
      '              value: "librenms-valkey"',
      '            - name: REDIS_PORT',
      '              value: "6379"',
      '            - name: REDIS_PASSWORD',
      '              valueFrom:',
      '                secretKeyRef:',
      '                  name: librenms-secrets',
      '                  key: redis_password',
      '            - name: RRDCACHED_SERVER',
      '              value: "librenms-rrdcached:42217"',
      '            - name: APP_KEY',
      '              valueFrom:',
      '                secretKeyRef:',
      '                  name: librenms-secrets',
      '                  key: app_key',
      '            - name: LIBRENMS_ADMIN_USER',
      `              value: ${yamlStr(config.adminUsername)}`,
      '            - name: LIBRENMS_ADMIN_EMAIL',
      `              value: ${yamlStr(config.adminEmail)}`,
      '            - name: LIBRENMS_ADMIN_PASSWORD',
      '              valueFrom:',
      '                secretKeyRef:',
      '                  name: librenms-secrets',
      '                  key: admin_password',
      '            - name: LIBRENMS_API_TOKEN',
      '              valueFrom:',
      '                secretKeyRef:',
      '                  name: librenms-secrets',
      '                  key: api_token',
      '            - name: LIBRENMS_LDAP_BIND_PASSWORD',
      '              valueFrom:',
      '                secretKeyRef:',
      '                  name: librenms-secrets',
      '                  key: ldap_bind_password',
    ];

    const sharedLibreNmsMounts = [
      '            - name: librenms-data',
      '              mountPath: /data',
      '            - name: librenms-config-dropins',
      '              mountPath: /data/config/axonwall_ldap.php',
      '              subPath: axonwall_ldap.php',
      '            - name: librenms-config-dropins',
      '              mountPath: /data/config/axonwall_discovery.php',
      '              subPath: axonwall_discovery.php',
    ];

    const sharedVolumes = [
      '      volumes:',
      '        - name: librenms-data',
      '          persistentVolumeClaim:',
      '            claimName: librenms-data',
      '        - name: librenms-config-dropins',
      '          configMap:',
      '            name: librenms-config-dropins',
    ];

    const docs = [
      [
        '# Auto-generated by Axonwall LibreNMS Plugin Compiler — do not edit manually',
        'apiVersion: v1',
        'kind: Namespace',
        'metadata:',
        `  name: ${yamlStr(namespace)}`,
        '  labels:',
        '    app.kubernetes.io/managed-by: axonwall',
      ].join('\n'),
      [
        '---',
        'apiVersion: v1',
        'kind: ConfigMap',
        'metadata:',
        '  name: librenms-config-dropins',
        `  namespace: ${yamlStr(namespace)}`,
        'data:',
        '  axonwall_ldap.php: |',
        indentMultiline(ldapConfigPhp.trimEnd(), 4),
        '  axonwall_discovery.php: |',
        indentMultiline(discoveryConfigPhp.trimEnd(), 4),
      ].join('\n'),
      [
        '---',
        'apiVersion: v1',
        'kind: Secret',
        'metadata:',
        '  name: librenms-secrets',
        `  namespace: ${yamlStr(namespace)}`,
        'type: Opaque',
        'stringData:',
        '  db_password: "__AXONWALL_LIBRENMS_DB_PASSWORD__"',
        '  db_root_password: "__AXONWALL_LIBRENMS_DB_ROOT_PASSWORD__"',
        '  redis_password: "__AXONWALL_LIBRENMS_DB_PASSWORD__"',
        '  app_key: "__AXONWALL_LIBRENMS_APP_KEY__"',
        '  admin_password: "__AXONWALL_LIBRENMS_ADMIN_PASSWORD__"',
        '  api_token: "__AXONWALL_LIBRENMS_API_TOKEN__"',
        '  ldap_bind_password: "__AXONWALL_LIBRENMS_LDAP_BIND_PASSWORD__"',
      ].join('\n'),
      [
        '---',
        'apiVersion: v1',
        'kind: PersistentVolumeClaim',
        'metadata:',
        '  name: librenms-db-data',
        `  namespace: ${yamlStr(namespace)}`,
        'spec:',
        '  accessModes:',
        '    - ReadWriteOnce',
        `  storageClassName: ${yamlStr(config.storageClass)}`,
        '  resources:',
        '    requests:',
        `      storage: ${yamlStr(`${config.dbVolumeSizeGb}Gi`)}`,
      ].join('\n'),
      [
        '---',
        'apiVersion: v1',
        'kind: PersistentVolumeClaim',
        'metadata:',
        '  name: librenms-data',
        `  namespace: ${yamlStr(namespace)}`,
        'spec:',
        '  accessModes:',
        '    - ReadWriteOnce',
        `  storageClassName: ${yamlStr(config.storageClass)}`,
        '  resources:',
        '    requests:',
        `      storage: ${yamlStr(`${config.dataVolumeSizeGb}Gi`)}`,
      ].join('\n'),
      [
        '---',
        'apiVersion: apps/v1',
        'kind: StatefulSet',
        'metadata:',
        '  name: librenms-mariadb',
        `  namespace: ${yamlStr(namespace)}`,
        'spec:',
        '  serviceName: librenms-mariadb',
        '  replicas: 1',
        '  selector:',
        '    matchLabels:',
        '      app: librenms-mariadb',
        '  template:',
        '    metadata:',
        '      labels:',
        '        app: librenms-mariadb',
        '    spec:',
        '      containers:',
        '        - name: mariadb',
        `          image: ${yamlStr(config.dbImage)}`,
        '          args:',
        '            - "--innodb-file-per-table=1"',
        '            - "--lower-case-table-names=0"',
        '          ports:',
        '            - containerPort: 3306',
        '          env:',
        '            - name: MARIADB_DATABASE',
        '              value: "librenms"',
        '            - name: MARIADB_USER',
        '              value: "librenms"',
        '            - name: MARIADB_PASSWORD',
        '              valueFrom:',
        '                secretKeyRef:',
        '                  name: librenms-secrets',
        '                  key: db_password',
        '            - name: MARIADB_ROOT_PASSWORD',
        '              valueFrom:',
        '                secretKeyRef:',
        '                  name: librenms-secrets',
        '                  key: db_root_password',
        '          volumeMounts:',
        '            - name: dbdata',
        '              mountPath: /var/lib/mysql',
        '      volumes:',
        '        - name: dbdata',
        '          persistentVolumeClaim:',
        '            claimName: librenms-db-data',
      ].join('\n'),
      [
        '---',
        'apiVersion: v1',
        'kind: Service',
        'metadata:',
        '  name: librenms-mariadb',
        `  namespace: ${yamlStr(namespace)}`,
        'spec:',
        '  selector:',
        '    app: librenms-mariadb',
        '  ports:',
        '    - name: mysql',
        '      port: 3306',
        '      targetPort: 3306',
      ].join('\n'),
      [
        '---',
        'apiVersion: apps/v1',
        'kind: Deployment',
        'metadata:',
        '  name: librenms-valkey',
        `  namespace: ${yamlStr(namespace)}`,
        'spec:',
        '  replicas: 1',
        '  selector:',
        '    matchLabels:',
        '      app: librenms-valkey',
        '  template:',
        '    metadata:',
        '      labels:',
        '        app: librenms-valkey',
        '    spec:',
        '      containers:',
        '        - name: valkey',
        `          image: ${yamlStr(config.valkeyImage)}`,
        '          command:',
        '            - sh',
        '            - -c',
        '            - exec valkey-server --appendonly yes --requirepass "$VALKEY_PASSWORD"',
        '          ports:',
        '            - containerPort: 6379',
        '          env:',
        '            - name: VALKEY_PASSWORD',
        '              valueFrom:',
        '                secretKeyRef:',
        '                  name: librenms-secrets',
        '                  key: redis_password',
      ].join('\n'),
      [
        '---',
        'apiVersion: v1',
        'kind: Service',
        'metadata:',
        '  name: librenms-valkey',
        `  namespace: ${yamlStr(namespace)}`,
        'spec:',
        '  selector:',
        '    app: librenms-valkey',
        '  ports:',
        '    - name: redis',
        '      port: 6379',
        '      targetPort: 6379',
      ].join('\n'),
      [
        '---',
        'apiVersion: networking.k8s.io/v1',
        'kind: NetworkPolicy',
        'metadata:',
        '  name: librenms-valkey-ingress',
        `  namespace: ${yamlStr(namespace)}`,
        'spec:',
        '  podSelector:',
        '    matchLabels:',
        '      app: librenms-valkey',
        '  policyTypes:',
        '    - Ingress',
        '  ingress:',
        '    - from:',
        '        - podSelector:',
        '            matchExpressions:',
        '              - key: app',
        '                operator: In',
        '                values:',
        '                  - librenms',
        '                  - librenms-dispatcher',
        '                  - librenms-syslogng',
        '                  - librenms-snmptrapd',
        '      ports:',
        '        - protocol: TCP',
        '          port: 6379',
      ].join('\n'),
      [
        '---',
        'apiVersion: apps/v1',
        'kind: Deployment',
        'metadata:',
        '  name: librenms-rrdcached',
        `  namespace: ${yamlStr(namespace)}`,
        'spec:',
        '  replicas: 1',
        '  selector:',
        '    matchLabels:',
        '      app: librenms-rrdcached',
        '  template:',
        '    metadata:',
        '      labels:',
        '        app: librenms-rrdcached',
        '    spec:',
        '      containers:',
        '        - name: rrdcached',
        `          image: ${yamlStr(config.image)}`,
        '          env:',
        '            - name: SIDECAR_RRDCACHED',
        '              value: "1"',
        '            - name: TZ',
        `              value: ${yamlStr(config.timezone || state?.system?.timezone || 'UTC')}`,
        '          ports:',
        '            - containerPort: 42217',
        '          volumeMounts:',
        '            - name: librenms-data',
        '              mountPath: /data',
        '      volumes:',
        '        - name: librenms-data',
        '          persistentVolumeClaim:',
        '            claimName: librenms-data',
      ].join('\n'),
      [
        '---',
        'apiVersion: v1',
        'kind: Service',
        'metadata:',
        '  name: librenms-rrdcached',
        `  namespace: ${yamlStr(namespace)}`,
        'spec:',
        '  selector:',
        '    app: librenms-rrdcached',
        '  ports:',
        '    - name: rrdcached',
        '      port: 42217',
        '      targetPort: 42217',
      ].join('\n'),
      [
        '---',
        'apiVersion: apps/v1',
        'kind: Deployment',
        'metadata:',
        '  name: librenms',
        `  namespace: ${yamlStr(namespace)}`,
        'spec:',
        '  replicas: 1',
        '  selector:',
        '    matchLabels:',
        '      app: librenms',
        '  template:',
        '    metadata:',
        '      labels:',
        '        app: librenms',
        '    spec:',
        '      containers:',
        '        - name: librenms',
        `          image: ${yamlStr(config.image)}`,
        '          ports:',
        '            - containerPort: 8000',
        '          readinessProbe:',
        '            httpGet:',
        '              path: /health',
        '              port: 8000',
        '            initialDelaySeconds: 30',
        '            periodSeconds: 15',
        '          env:',
        ...sharedLibreNmsEnv,
        '          volumeMounts:',
        ...sharedLibreNmsMounts,
        ...sharedVolumes,
      ].join('\n'),
      [
        '---',
        'apiVersion: v1',
        'kind: Service',
        'metadata:',
        '  name: librenms',
        `  namespace: ${yamlStr(namespace)}`,
        'spec:',
        '  selector:',
        '    app: librenms',
        '  ports:',
        '    - name: http',
        `      port: ${config.servicePort}`,
        '      targetPort: 8000',
      ].join('\n'),
      [
        '---',
        'apiVersion: apps/v1',
        'kind: Deployment',
        'metadata:',
        '  name: librenms-dispatcher',
        `  namespace: ${yamlStr(namespace)}`,
        'spec:',
        '  replicas: 1',
        '  selector:',
        '    matchLabels:',
        '      app: librenms-dispatcher',
        '  template:',
        '    metadata:',
        '      labels:',
        '        app: librenms-dispatcher',
        '    spec:',
        '      containers:',
        '        - name: librenms-dispatcher',
        `          image: ${yamlStr(config.image)}`,
        '          env:',
        '            - name: SIDECAR_DISPATCHER',
        '              value: "1"',
        '            - name: DISPATCHER_NODE_ID',
        '              value: "dispatcher1"',
        ...sharedLibreNmsEnv,
        '          volumeMounts:',
        ...sharedLibreNmsMounts,
        ...sharedVolumes,
      ].join('\n'),
    ];

    if (config.syslogEnabled) {
      docs.push(
        [
          '---',
          'apiVersion: apps/v1',
          'kind: Deployment',
          'metadata:',
          '  name: librenms-syslogng',
          `  namespace: ${yamlStr(namespace)}`,
          'spec:',
          '  replicas: 1',
          '  selector:',
          '    matchLabels:',
          '      app: librenms-syslogng',
          '  template:',
          '    metadata:',
          '      labels:',
          '        app: librenms-syslogng',
          '    spec:',
          '      containers:',
          '        - name: librenms-syslogng',
          `          image: ${yamlStr(config.image)}`,
          '          env:',
          '            - name: SIDECAR_SYSLOGNG',
          '              value: "1"',
          ...sharedLibreNmsEnv,
          '          ports:',
          '            - name: syslog-udp',
          '              containerPort: 514',
          '              protocol: UDP',
          '          volumeMounts:',
          ...sharedLibreNmsMounts,
          ...sharedVolumes,
        ].join('\n'),
        [
          '---',
          'apiVersion: v1',
          'kind: Service',
          'metadata:',
          '  name: librenms-syslog',
          `  namespace: ${yamlStr(namespace)}`,
          'spec:',
          '  selector:',
          '    app: librenms-syslogng',
          '  ports:',
          '    - name: syslog-udp',
          '      port: 514',
          '      targetPort: 514',
          '      protocol: UDP',
        ].join('\n'),
      );
    }

    if (config.snmpTrapEnabled) {
      docs.push(
        [
          '---',
          'apiVersion: apps/v1',
          'kind: Deployment',
          'metadata:',
          '  name: librenms-snmptrapd',
          `  namespace: ${yamlStr(namespace)}`,
          'spec:',
          '  replicas: 1',
          '  selector:',
          '    matchLabels:',
          '      app: librenms-snmptrapd',
          '  template:',
          '    metadata:',
          '      labels:',
          '        app: librenms-snmptrapd',
          '    spec:',
          '      containers:',
          '        - name: librenms-snmptrapd',
          `          image: ${yamlStr(config.image)}`,
          '          env:',
          '            - name: SIDECAR_SNMPTRAPD',
          '              value: "1"',
          ...sharedLibreNmsEnv,
          '          ports:',
          '            - name: snmptrap-udp',
          '              containerPort: 162',
          '              protocol: UDP',
          '          volumeMounts:',
          ...sharedLibreNmsMounts,
          ...sharedVolumes,
        ].join('\n'),
        [
          '---',
          'apiVersion: v1',
          'kind: Service',
          'metadata:',
          '  name: librenms-snmptrapd',
          `  namespace: ${yamlStr(namespace)}`,
          'spec:',
          '  selector:',
          '    app: librenms-snmptrapd',
          '  ports:',
          '    - name: snmptrap-udp',
          '      port: 162',
          '      targetPort: 162',
          '      protocol: UDP',
        ].join('\n'),
      );
    }

    if (ingressDoc) {
      docs.push(ingressDoc);
    }

    k3sManifestsYaml = `${docs.join('\n')}\n`;
  }

  return {
    enabled,
    k3sDependencyMet,
    mode,
    config,
    namespace,
    domain,
    endpointUrl,
    internalServiceUrl,
    lanIp,
    baseDn,
    bindDn,
    podLdapUrl,
    ldapConfigPhp,
    discoveryConfigPhp,
    unboundOverrides,
    k3sManifestsYaml,
    enrollmentPlan,
  };
}
