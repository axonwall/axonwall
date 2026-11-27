import {
  NetBoxConfigSchema,
  type DesiredState,
  type NetBoxConfig,
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

export interface NetBoxPlannedVrf {
  name: string;
  rd?: string;
  enforceUnique: boolean;
  description: string;
}

export interface NetBoxPlannedVlan {
  vid: number;
  name: string;
  parentInterface: string;
  description: string;
}

export interface NetBoxPlannedInterface {
  name: string;
  device: string;
  type: string;
  enabled: boolean;
  mtu: number;
  role: string;
  ipv4Address?: string;
  ipv6Address?: string;
  description: string;
}

export interface NetBoxPlannedPrefix {
  prefix: string;
  family: 4 | 6;
  vrf?: string;
  status: 'active';
  description: string;
}

export interface NetBoxPlannedIpAddress {
  address: string;
  vrf?: string;
  interfaceName?: string;
  role?: 'vip' | 'anycast' | 'loopback' | 'secondary';
  status: 'active' | 'dhcp' | 'reserved';
  dnsName?: string;
  description: string;
}

export interface NetBoxPlannedVirtualMachine {
  name: string;
  kind: 'kvm' | 'lxc';
  vcpus: number;
  memoryMb: number;
  diskGb: number;
  status: 'active' | 'offline';
  primaryIp?: string;
  comments: string;
}

export interface NetBoxSyncPlan {
  site: {
    name: string;
    slug: string;
  };
  device: {
    hostname: string;
    domain: string;
    primaryIp?: string;
    siteSlug: string;
  };
  vrfs: NetBoxPlannedVrf[];
  vlans: NetBoxPlannedVlan[];
  interfaces: NetBoxPlannedInterface[];
  prefixes: NetBoxPlannedPrefix[];
  ipAddresses: NetBoxPlannedIpAddress[];
  virtualMachines: NetBoxPlannedVirtualMachine[];
  k3sCluster: {
    enabled: boolean;
    cniPlugin: string;
    clusterCidr: string;
    serviceCidr: string;
    haTopology: string;
  };
  summary: {
    vrfsCount: number;
    vlansCount: number;
    interfacesCount: number;
    prefixesCount: number;
    ipAddressesCount: number;
    virtualMachinesCount: number;
    totalObjects: number;
  };
}

export interface CompiledNetBoxBundle {
  enabled: boolean;
  k3sDependencyMet: boolean;
  config: NetBoxConfig;
  namespace: string;
  domain: string;
  endpointUrl: string;
  internalServiceUrl: string;
  lanIp: string;
  baseDn: string;
  bindDn: string;
  podLdapUrl: string;
  extraPy: string;
  ldapConfigPy: string;
  unboundOverrides: string;
  k3sManifestsYaml: string;
  syncPlan: NetBoxSyncPlan;
}

export function resolveNetBoxConfig(state?: Partial<DesiredState> | null): NetBoxConfig {
  const parsed = NetBoxConfigSchema.parse(state?.netbox ?? {});
  const enabled = isPluginEnabled('netbox', state);
  return {
    ...parsed,
    enabled,
  };
}

function normalizeIpv4Cidr(rawCidr: string): string | null {
  const parts = rawCidr.trim().split('/');
  if (parts.length !== 2) return null;
  const ip = parts[0]!.trim();
  const prefix = Number.parseInt(parts[1]!.trim(), 10);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  const octets = ip.split('.').map((o) => Number.parseInt(o, 10));
  if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) {
    return null;
  }
  const ipInt =
    ((octets[0]! << 24) >>> 0) |
    ((octets[1]! << 16) >>> 0) |
    ((octets[2]! << 8) >>> 0) |
    (octets[3]! >>> 0);
  const mask = prefix === 0 ? 0 : (~((1 << (32 - prefix)) - 1) >>> 0);
  const netInt = (ipInt & mask) >>> 0;
  const netIp = [
    (netInt >>> 24) & 0xff,
    (netInt >>> 16) & 0xff,
    (netInt >>> 8) & 0xff,
    netInt & 0xff,
  ].join('.');
  return `${netIp}/${prefix}`;
}

function normalizePrefix(raw: string): { cidr: string; family: 4 | 6 } | null {
  const trimmed = raw.trim();
  if (!trimmed.includes('/')) return null;
  if (trimmed.includes(':')) {
    const [, lenStr] = trimmed.split('/');
    const len = Number.parseInt(lenStr ?? '', 10);
    if (!Number.isInteger(len) || len < 0 || len > 128) return null;
    return { cidr: trimmed, family: 6 };
  }
  const norm = normalizeIpv4Cidr(trimmed);
  return norm ? { cidr: norm, family: 4 } : null;
}

function ensureHostCidr(rawIp: string, defaultPrefix = 32): string | null {
  const trimmed = rawIp.trim();
  if (!trimmed) return null;
  if (trimmed.includes('/')) return trimmed;
  if (trimmed.includes(':')) return `${trimmed}/128`;
  return `${trimmed}/${defaultPrefix}`;
}

export function buildNetBoxSyncPlan(state: Partial<DesiredState>): NetBoxSyncPlan {
  const config = NetBoxConfigSchema.parse(state.netbox ?? {});
  const syncCfg = config.sync;
  const hostname = state.system?.hostname?.trim() || 'axonwall-fw';
  const domain = state.system?.domain?.trim() || 'axonwall.local';
  const primaryIp = resolveApplianceLanIp(state);

  const vrfs: NetBoxPlannedVrf[] = [];
  if (syncCfg.syncVrfs) {
    for (const vrf of state.vrfs ?? []) {
      vrfs.push({
        name: vrf.name,
        rd: vrf.tableId ? `65000:${vrf.tableId}` : undefined,
        enforceUnique: true,
        description: vrf.description || `Axonwall VRF ${vrf.name}`,
      });
    }
  }

  const vlans: NetBoxPlannedVlan[] = [];
  if (syncCfg.syncVlans) {
    for (const vlan of state.vlans ?? []) {
      vlans.push({
        vid: vlan.tag,
        name: vlan.vlanInterface || `vlan${vlan.tag}`,
        parentInterface: vlan.parentInterface,
        description: vlan.description || `802.1Q VLAN ${vlan.tag} on ${vlan.parentInterface}`,
      });
    }
  }

  const interfaces: NetBoxPlannedInterface[] = [];
  const prefixMap = new Map<string, NetBoxPlannedPrefix>();
  const ipMap = new Map<string, NetBoxPlannedIpAddress>();

  const addPrefix = (raw: string | undefined, description: string, vrf?: string) => {
    if (!syncCfg.syncPrefixes || !raw) return;
    const norm = normalizePrefix(raw);
    if (!norm) return;
    if (!prefixMap.has(norm.cidr)) {
      prefixMap.set(norm.cidr, {
        prefix: norm.cidr,
        family: norm.family,
        vrf,
        status: 'active',
        description,
      });
    }
  };

  const addIp = (entry: NetBoxPlannedIpAddress) => {
    const key = `${entry.address}|${entry.vrf ?? ''}`;
    if (!ipMap.has(key)) {
      ipMap.set(key, entry);
    }
  };

  for (const iface of state.interfaces ?? []) {
    const ip4 = (iface.ipv4Address || (iface as { address?: string }).address || '').trim();
    const ip6 = (iface.ipv6Address || '').trim();
    const devName = iface.device || iface.name;
    if (syncCfg.syncInterfaces) {
      interfaces.push({
        name: devName,
        device: hostname,
        type: 'other',
        enabled: iface.enabled !== false,
        mtu: iface.mtu ?? 1500,
        role: iface.role || 'lan',
        ipv4Address: ip4 || undefined,
        ipv6Address: ip6 || undefined,
        description: iface.description || `Axonwall ${iface.role} (${iface.name})`,
      });
    }
    if (ip4) {
      addPrefix(ip4, `Interface ${iface.name} (${devName}) IPv4 subnet`);
      const addr = ensureHostCidr(ip4, 24);
      if (addr) {
        addIp({
          address: addr,
          interfaceName: devName,
          status: 'active',
          dnsName: iface.role === 'lan' ? `${hostname}.${domain}` : undefined,
          description: `Interface ${iface.name} (${devName})`,
        });
      }
    }
    if (ip6) {
      addPrefix(ip6, `Interface ${iface.name} (${devName}) IPv6 subnet`);
      const addr6 = ensureHostCidr(ip6, 64);
      if (addr6) {
        addIp({
          address: addr6,
          interfaceName: devName,
          status: 'active',
          description: `Interface ${iface.name} (${devName}) IPv6`,
        });
      }
    }
  }

  if (syncCfg.syncInterfaces) {
    for (const vlan of state.vlans ?? []) {
      interfaces.push({
        name: vlan.vlanInterface || `${vlan.parentInterface}.${vlan.tag}`,
        device: hostname,
        type: 'virtual',
        enabled: true,
        mtu: 1500,
        role: 'vlan',
        description: vlan.description || `VLAN ${vlan.tag} (${vlan.vlanInterface})`,
      });
    }
    for (const br of state.bridges ?? []) {
      interfaces.push({
        name: br.name,
        device: hostname,
        type: 'bridge',
        enabled: true,
        mtu: 1500,
        role: 'bridge',
        description: br.description || `Bridge (${(br.members ?? []).map((m) => m.interface).join(', ')})`,
      });
    }
    for (const bond of state.bonds ?? []) {
      interfaces.push({
        name: bond.name,
        device: hostname,
        type: 'lag',
        enabled: true,
        mtu: 1500,
        role: 'bond',
        description: bond.description || `LAG ${bond.mode} (${(bond.members ?? []).join(', ')})`,
      });
    }
  }

  if (state.wireguard?.enabled) {
    if (syncCfg.syncInterfaces) {
      interfaces.push({
        name: 'wg0',
        device: hostname,
        type: 'virtual',
        enabled: true,
        mtu: 1420,
        role: 'vpn',
        ipv4Address: state.wireguard.address,
        description: `WireGuard tunnel (UDP/${state.wireguard.listenPort})`,
      });
    }
    if (state.wireguard.address) {
      addPrefix(state.wireguard.address, 'WireGuard tunnel network');
      const wgAddr = ensureHostCidr(state.wireguard.address, 24);
      if (wgAddr) {
        addIp({
          address: wgAddr,
          interfaceName: 'wg0',
          status: 'active',
          description: 'WireGuard local endpoint',
        });
      }
    }
  }

  for (const sub of state.dhcp?.subnets ?? []) {
    addPrefix(sub.subnet, `Kea DHCPv4 subnet (${sub.interface})`);
    for (const stMap of sub.staticMappings ?? []) {
      const hostCidr = ensureHostCidr(stMap.ip, 32);
      if (hostCidr) {
        addIp({
          address: hostCidr,
          status: 'dhcp',
          dnsName: stMap.hostname ? `${stMap.hostname}.${domain}` : undefined,
          description: `DHCP static reservation (${stMap.mac})`,
        });
      }
    }
  }

  if (syncCfg.syncVirtualIps) {
    for (const vip of state.virtualIps ?? []) {
      const vipAddr = ensureHostCidr(vip.ip, 24);
      if (vipAddr) {
        addIp({
          address: vipAddr,
          interfaceName: vip.interface,
          role: vip.type === 'carp' ? 'vip' : 'secondary',
          status: 'active',
          description: vip.description || `Virtual IP (${vip.type}) on ${vip.interface}`,
        });
      }
    }
    for (const vi of state.ha?.vrrpInstances ?? []) {
      for (const rawVip of vi.virtualIps ?? []) {
        const vipAddr = ensureHostCidr(rawVip, 24);
        if (vipAddr) {
          addIp({
            address: vipAddr,
            interfaceName: vi.interface,
            role: 'vip',
            status: 'active',
            description: `HA VRRP VIP (VRID ${vi.vrid} • ${vi.name})`,
          });
        }
      }
    }
  }

  if (state.k3s?.enabled) {
    addPrefix(state.k3s.clusterCidr, 'K3s Pod Cluster CIDR');
    addPrefix(state.k3s.serviceCidr, 'K3s Service ClusterIP CIDR');
  }

  const virtualMachines: NetBoxPlannedVirtualMachine[] = [];
  if (syncCfg.syncVirtualMachines && state.virt) {
    for (const vm of state.virt.vms ?? []) {
      const totalDiskGb = (vm.disks ?? []).reduce((sum, d) => sum + (d.sizeGb ?? 0), 0) || 32;
      const ipMatch = vm.cloudInit?.ipConfig?.match(/\bip=([^\s,]+)/i);
      virtualMachines.push({
        name: vm.name,
        kind: 'kvm',
        vcpus: vm.cores ?? 2,
        memoryMb: vm.memoryMb ?? 2048,
        diskGb: totalDiskGb,
        status: vm.enabled === false ? 'offline' : 'active',
        primaryIp: ipMatch?.[1] && ipMatch[1].toLowerCase() !== 'dhcp' ? ipMatch[1] : undefined,
        comments: `KVM VM #${vm.vmid} (${vm.osType || 'linux'})`,
      });
    }
    for (const ct of state.virt.containers ?? []) {
      virtualMachines.push({
        name: ct.hostname,
        kind: 'lxc',
        vcpus: ct.cores ?? 2,
        memoryMb: ct.memoryMb ?? 512,
        diskGb: ct.rootfsSizeGb ?? 8,
        status: ct.enabled === false ? 'offline' : 'active',
        comments: `LXC CT #${ct.ctid} (${ct.template})`,
      });
    }
  }

  const prefixes = Array.from(prefixMap.values());
  const ipAddresses = Array.from(ipMap.values());
  const totalObjects =
    vrfs.length +
    vlans.length +
    interfaces.length +
    prefixes.length +
    ipAddresses.length +
    virtualMachines.length +
    1; // appliance device

  return {
    site: {
      name: config.siteName,
      slug: config.siteSlug,
    },
    device: {
      hostname,
      domain,
      primaryIp,
      siteSlug: config.siteSlug,
    },
    vrfs,
    vlans,
    interfaces,
    prefixes,
    ipAddresses,
    virtualMachines,
    k3sCluster: {
      enabled: Boolean(state.k3s?.enabled),
      cniPlugin: state.k3s?.cniPlugin ?? 'flannel',
      clusterCidr: state.k3s?.clusterCidr ?? '10.42.0.0/16',
      serviceCidr: state.k3s?.serviceCidr ?? '10.43.0.0/16',
      haTopology: state.k3s?.haTopology ?? 'embedded-etcd',
    },
    summary: {
      vrfsCount: vrfs.length,
      vlansCount: vlans.length,
      interfacesCount: interfaces.length,
      prefixesCount: prefixes.length,
      ipAddressesCount: ipAddresses.length,
      virtualMachinesCount: virtualMachines.length,
      totalObjects,
    },
  };
}

export function compileNetBoxBundle(state: Partial<DesiredState>): CompiledNetBoxBundle {
  const config = resolveNetBoxConfig(state);
  const k3sDependencyMet = isPluginEnabled('core-k3s', state);
  const enabled = config.enabled && k3sDependencyMet;
  const lanIp = resolveApplianceLanIp(state);
  const namespace = config.namespace || 'netbox';
  const domain = config.domain || 'netbox.axonwall.local';
  const proto = config.ingressTls ? 'https' : 'http';
  const endpointUrl = config.externalUrl?.trim() || `${proto}://${domain}`;
  const internalServiceUrl = `http://netbox.${namespace}.svc.cluster.local:${config.servicePort}`;

  const ldap = config.ldapAuth;
  const baseDn =
    ldap.baseDn?.trim() ||
    state.identity?.baseDn?.trim() ||
    deriveBaseDn(state.system?.domain || 'axonwall.local');
  const bindDn = ldap.bindDn?.trim() || `cn=svc-netbox,ou=services,${baseDn}`;
  const podLdapUrl = rewritePodLdapUrl(ldap.url || 'ldap://127.0.0.1:389', lanIp);

  const allowedHosts = Array.from(
    new Set(
      [
        domain,
        'netbox',
        `netbox.${namespace}.svc.cluster.local`,
        'localhost',
        '127.0.0.1',
        ...(lanIp ? [lanIp] : []),
      ].filter(Boolean),
    ),
  );
  const useXForwardedHost = Boolean(
    (config as { trustedProxy?: boolean; useXForwardedHost?: boolean }).trustedProxy ||
      (config as { useXForwardedHost?: boolean }).useXForwardedHost,
  );
  const csrfOrigins = [`https://${domain}`, `http://${domain}`, `http://127.0.0.1:${config.servicePort}`];

  const extraPy = [
    '# Axonwall-managed NetBox runtime overrides',
    `ALLOWED_HOSTS = ${JSON.stringify(allowedHosts)}`,
    `CSRF_TRUSTED_ORIGINS = ${JSON.stringify(csrfOrigins)}`,
    "SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')",
    `USE_X_FORWARDED_HOST = ${useXForwardedHost ? 'True' : 'False'}`,
    'METRICS_ENABLED = True',
    `TIME_ZONE = ${JSON.stringify(state.system?.timezone || 'UTC')}`,
    '',
  ].join('\n');

  const ldapConfigPy = ldap.enabled
    ? [
        '# Axonwall OpenLDAP integration (cn=svc-netbox)',
        'import os',
        'import ldap',
        'from django_auth_ldap.config import LDAPSearch, PosixGroupType',
        '',
        `AUTH_LDAP_SERVER_URI = ${JSON.stringify(podLdapUrl)}`,
        `AUTH_LDAP_BIND_DN = ${JSON.stringify(bindDn)}`,
        "AUTH_LDAP_BIND_PASSWORD = os.environ.get('AUTH_LDAP_BIND_PASSWORD', '')",
        'AUTH_LDAP_CONNECTION_OPTIONS = {ldap.OPT_REFERRALS: 0}',
        `AUTH_LDAP_START_TLS = ${Boolean((ldap as { startTls?: boolean }).startTls) ? 'True' : 'False'}`,
        '',
        'AUTH_LDAP_USER_SEARCH = LDAPSearch(',
        `    ${JSON.stringify(`ou=users,${baseDn}`)},`,
        '    ldap.SCOPE_SUBTREE,',
        '    "(uid=%(user)s)",',
        ')',
        'AUTH_LDAP_GROUP_SEARCH = LDAPSearch(',
        `    ${JSON.stringify(`ou=groups,${baseDn}`)},`,
        '    ldap.SCOPE_SUBTREE,',
        '    "(objectClass=posixGroup)",',
        ')',
        'AUTH_LDAP_GROUP_TYPE = PosixGroupType()',
        '',
        'AUTH_LDAP_USER_ATTR_MAP = {',
        '    "first_name": "givenName",',
        '    "last_name": "sn",',
        '    "email": "mail",',
        '}',
        '',
        'AUTH_LDAP_USER_FLAGS_BY_GROUP = {',
        `    "is_active": ${JSON.stringify(`cn=${ldap.readonlyGroups[0] || 'netbox-readonly'},ou=groups,${baseDn}`)},`,
        `    "is_staff": ${JSON.stringify(`cn=${ldap.operatorGroups[0] || 'netbox-operator'},ou=groups,${baseDn}`)},`,
        `    "is_superuser": ${JSON.stringify(`cn=${ldap.adminGroups[0] || 'axonwall-admin'},ou=groups,${baseDn}`)},`,
        '}',
        'AUTH_LDAP_ALWAYS_UPDATE_USER = True',
        'AUTH_LDAP_FIND_GROUP_PERMS = True',
        '',
      ].join('\n')
    : '# OpenLDAP authentication disabled in /etc/axonwall/services.yaml\n';

  const unboundOverrides =
    enabled && config.syncUnboundDns && lanIp
      ? buildUnboundLocalDataOverride('Auto-generated by Axonwall NetBox Plugin Compiler', domain, lanIp)
      : '';

  const syncPlan = buildNetBoxSyncPlan(state);

  let k3sManifestsYaml = '';
  if (enabled) {
    const tlsBlock = config.ingressTls
      ? [
          '  tls:',
          '    - hosts:',
          `        - ${yamlStr(domain)}`,
          '      secretName: netbox-tls',
        ].join('\n')
      : '';

    const ingressDoc = config.ingressEnabled
      ? [
          '---',
          'apiVersion: networking.k8s.io/v1',
          'kind: Ingress',
          'metadata:',
          '  name: netbox-ingress',
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
          '                name: netbox',
          '                port:',
          `                  number: ${config.servicePort}`,
        ].join('\n')
      : '';

    const sharedNetBoxEnv = [
      '            - name: DB_HOST',
      '              value: "netbox-postgres"',
      '            - name: DB_PORT',
      '              value: "5432"',
      '            - name: DB_NAME',
      '              value: "netbox"',
      '            - name: DB_USER',
      '              value: "netbox"',
      '            - name: DB_PASSWORD',
      '              valueFrom:',
      '                secretKeyRef:',
      '                  name: netbox-secrets',
      '                  key: db_password',
      '            - name: REDIS_HOST',
      '              value: "netbox-valkey"',
      '            - name: REDIS_PORT',
      '              value: "6379"',
      '            - name: REDIS_DATABASE',
      '              value: "0"',
      '            - name: REDIS_PASSWORD',
      '              valueFrom:',
      '                secretKeyRef:',
      '                  name: netbox-secrets',
      '                  key: redis_password',
      '            - name: REDIS_CACHE_HOST',
      '              value: "netbox-valkey"',
      '            - name: REDIS_CACHE_PORT',
      '              value: "6379"',
      '            - name: REDIS_CACHE_DATABASE',
      '              value: "1"',
      '            - name: REDIS_CACHE_PASSWORD',
      '              valueFrom:',
      '                secretKeyRef:',
      '                  name: netbox-secrets',
      '                  key: redis_password',
      '            - name: SECRET_KEY',
      '              valueFrom:',
      '                secretKeyRef:',
      '                  name: netbox-secrets',
      '                  key: secret_key',
      '            - name: SKIP_SUPERUSER',
      '              value: "false"',
      '            - name: SUPERUSER_NAME',
      `              value: ${yamlStr(config.superuserUsername)}`,
      '            - name: SUPERUSER_EMAIL',
      `              value: ${yamlStr(config.superuserEmail)}`,
      '            - name: SUPERUSER_PASSWORD',
      '              valueFrom:',
      '                secretKeyRef:',
      '                  name: netbox-secrets',
      '                  key: superuser_password',
      '            - name: SUPERUSER_API_TOKEN',
      '              valueFrom:',
      '                secretKeyRef:',
      '                  name: netbox-secrets',
      '                  key: superuser_api_token',
      '            - name: REMOTE_AUTH_ENABLED',
      `              value: ${yamlStr(ldap.enabled ? 'True' : 'False')}`,
      ...(ldap.enabled
        ? [
            '            - name: REMOTE_AUTH_BACKEND',
            '              value: "netbox.authentication.LDAPBackend"',
            '            - name: AUTH_LDAP_BIND_PASSWORD',
            '              valueFrom:',
            '                secretKeyRef:',
            '                  name: netbox-secrets',
            '                  key: ldap_bind_password',
          ]
        : []),
    ];

    const sharedNetBoxMounts = [
      '            - name: netbox-media',
      '              mountPath: /opt/netbox/netbox/media',
      '            - name: netbox-extra-config',
      '              mountPath: /etc/netbox/config/extra.py',
      '              subPath: extra.py',
      ...(ldap.enabled
        ? [
            '            - name: netbox-extra-config',
            '              mountPath: /etc/netbox/config/ldap/ldap_config.py',
            '              subPath: ldap_config.py',
          ]
        : []),
    ];

    const docs = [
      [
        '# Auto-generated by Axonwall NetBox Plugin Compiler — do not edit manually',
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
        '  name: netbox-extra-config',
        `  namespace: ${yamlStr(namespace)}`,
        'data:',
        '  extra.py: |',
        indentMultiline(extraPy.trimEnd(), 4),
        '  ldap_config.py: |',
        indentMultiline(ldapConfigPy.trimEnd(), 4),
      ].join('\n'),
      [
        '---',
        'apiVersion: v1',
        'kind: Secret',
        'metadata:',
        '  name: netbox-secrets',
        `  namespace: ${yamlStr(namespace)}`,
        'type: Opaque',
        'stringData:',
        '  db_password: "__AXONWALL_NETBOX_DB_PASSWORD__"',
        '  redis_password: "__AXONWALL_NETBOX_REDIS_PASSWORD__"',
        '  secret_key: "__AXONWALL_NETBOX_SECRET_KEY__"',
        '  superuser_password: "__AXONWALL_NETBOX_SUPERUSER_PASSWORD__"',
        '  superuser_api_token: "__AXONWALL_NETBOX_API_TOKEN__"',
        '  ldap_bind_password: "__AXONWALL_NETBOX_LDAP_BIND_PASSWORD__"',
      ].join('\n'),
      [
        '---',
        'apiVersion: v1',
        'kind: PersistentVolumeClaim',
        'metadata:',
        '  name: netbox-postgres-data',
        `  namespace: ${yamlStr(namespace)}`,
        'spec:',
        '  accessModes:',
        '    - ReadWriteOnce',
        `  storageClassName: ${yamlStr(config.storageClass)}`,
        '  resources:',
        '    requests:',
        `      storage: ${yamlStr(`${config.postgresStorageGb}Gi`)}`,
      ].join('\n'),
      [
        '---',
        'apiVersion: v1',
        'kind: PersistentVolumeClaim',
        'metadata:',
        '  name: netbox-media',
        `  namespace: ${yamlStr(namespace)}`,
        'spec:',
        '  accessModes:',
        '    - ReadWriteOnce',
        `  storageClassName: ${yamlStr(config.storageClass)}`,
        '  resources:',
        '    requests:',
        `      storage: ${yamlStr(`${config.mediaStorageGb}Gi`)}`,
      ].join('\n'),
      [
        '---',
        'apiVersion: apps/v1',
        'kind: StatefulSet',
        'metadata:',
        '  name: netbox-postgres',
        `  namespace: ${yamlStr(namespace)}`,
        'spec:',
        '  serviceName: netbox-postgres',
        '  replicas: 1',
        '  selector:',
        '    matchLabels:',
        '      app: netbox-postgres',
        '  template:',
        '    metadata:',
        '      labels:',
        '        app: netbox-postgres',
        '    spec:',
        '      containers:',
        '        - name: postgres',
        `          image: ${yamlStr(config.postgresImage)}`,
        '          ports:',
        '            - containerPort: 5432',
        '          env:',
        '            - name: POSTGRES_DB',
        '              value: "netbox"',
        '            - name: POSTGRES_USER',
        '              value: "netbox"',
        '            - name: POSTGRES_PASSWORD',
        '              valueFrom:',
        '                secretKeyRef:',
        '                  name: netbox-secrets',
        '                  key: db_password',
        '            - name: PGDATA',
        '              value: "/var/lib/postgresql/data/pgdata"',
        '          readinessProbe:',
        '            exec:',
        '              command: ["pg_isready", "-U", "netbox"]',
        '            initialDelaySeconds: 10',
        '            periodSeconds: 10',
        '          volumeMounts:',
        '            - name: pgdata',
        '              mountPath: /var/lib/postgresql/data',
        '      volumes:',
        '        - name: pgdata',
        '          persistentVolumeClaim:',
        '            claimName: netbox-postgres-data',
      ].join('\n'),
      [
        '---',
        'apiVersion: v1',
        'kind: Service',
        'metadata:',
        '  name: netbox-postgres',
        `  namespace: ${yamlStr(namespace)}`,
        'spec:',
        '  selector:',
        '    app: netbox-postgres',
        '  ports:',
        '    - name: postgres',
        '      port: 5432',
        '      targetPort: 5432',
      ].join('\n'),
      [
        '---',
        'apiVersion: apps/v1',
        'kind: StatefulSet',
        'metadata:',
        '  name: netbox-valkey',
        `  namespace: ${yamlStr(namespace)}`,
        'spec:',
        '  serviceName: netbox-valkey',
        '  replicas: 1',
        '  selector:',
        '    matchLabels:',
        '      app: netbox-valkey',
        '  template:',
        '    metadata:',
        '      labels:',
        '        app: netbox-valkey',
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
        '                  name: netbox-secrets',
        '                  key: redis_password',
      ].join('\n'),
      [
        '---',
        'apiVersion: v1',
        'kind: Service',
        'metadata:',
        '  name: netbox-valkey',
        `  namespace: ${yamlStr(namespace)}`,
        'spec:',
        '  selector:',
        '    app: netbox-valkey',
        '  ports:',
        '    - name: redis',
        '      port: 6379',
        '      targetPort: 6379',
      ].join('\n'),
      [
        '---',
        'apiVersion: apps/v1',
        'kind: Deployment',
        'metadata:',
        '  name: netbox',
        `  namespace: ${yamlStr(namespace)}`,
        'spec:',
        `  replicas: ${config.replicas}`,
        '  selector:',
        '    matchLabels:',
        '      app: netbox',
        '  template:',
        '    metadata:',
        '      labels:',
        '        app: netbox',
        '    spec:',
        '      containers:',
        '        - name: netbox',
        `          image: ${yamlStr(config.image)}`,
        '          ports:',
        '            - containerPort: 8080',
        '          env:',
        ...sharedNetBoxEnv,
        '          readinessProbe:',
        '            httpGet:',
        '              path: /login/',
        '              port: 8080',
        '            initialDelaySeconds: 45',
        '            periodSeconds: 15',
        '          volumeMounts:',
        ...sharedNetBoxMounts,
        '      volumes:',
        '        - name: netbox-media',
        '          persistentVolumeClaim:',
        '            claimName: netbox-media',
        '        - name: netbox-extra-config',
        '          configMap:',
        '            name: netbox-extra-config',
      ].join('\n'),
      [
        '---',
        'apiVersion: v1',
        'kind: Service',
        'metadata:',
        '  name: netbox',
        `  namespace: ${yamlStr(namespace)}`,
        'spec:',
        '  selector:',
        '    app: netbox',
        '  ports:',
        '    - name: http',
        `      port: ${config.servicePort}`,
        '      targetPort: 8080',
      ].join('\n'),
      [
        '---',
        'apiVersion: apps/v1',
        'kind: Deployment',
        'metadata:',
        '  name: netbox-worker',
        `  namespace: ${yamlStr(namespace)}`,
        'spec:',
        `  replicas: ${config.workerReplicas}`,
        '  selector:',
        '    matchLabels:',
        '      app: netbox-worker',
        '  template:',
        '    metadata:',
        '      labels:',
        '        app: netbox-worker',
        '    spec:',
        '      containers:',
        '        - name: netbox-worker',
        `          image: ${yamlStr(config.image)}`,
        '          command:',
        '            - /opt/netbox/venv/bin/python',
        '            - /opt/netbox/netbox/manage.py',
        '            - rqworker',
        '          env:',
        ...sharedNetBoxEnv,
        '          volumeMounts:',
        ...sharedNetBoxMounts,
        '      volumes:',
        '        - name: netbox-media',
        '          persistentVolumeClaim:',
        '            claimName: netbox-media',
        '        - name: netbox-extra-config',
        '          configMap:',
        '            name: netbox-extra-config',
      ].join('\n'),
    ];

    if (ingressDoc) {
      docs.push(ingressDoc);
    }

    k3sManifestsYaml = `${docs.join('\n')}\n`;
  }

  return {
    enabled,
    k3sDependencyMet,
    config,
    namespace,
    domain,
    endpointUrl,
    internalServiceUrl,
    lanIp,
    baseDn,
    bindDn,
    podLdapUrl,
    extraPy,
    ldapConfigPy,
    unboundOverrides,
    k3sManifestsYaml,
    syncPlan,
  };
}
