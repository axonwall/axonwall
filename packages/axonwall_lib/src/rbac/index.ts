/**
 * Axonwall RBAC (Role-Based Access Control)
 * Granular privileges matching and modernizing OPNsense page permissions.
 */

export const PRIVILEGES = [
  'firewall.rules.read',
  'firewall.rules.write',
  'firewall.aliases.read',
  'firewall.aliases.write',
  'firewall.nat.read',
  'firewall.nat.write',
  'interfaces.read',
  'interfaces.write',
  'routing.read',
  'routing.write',
  'services.dhcp.read',
  'services.dhcp.write',
  'services.dns.read',
  'services.dns.write',
  'vpn.wireguard.read',
  'vpn.wireguard.write',
  'system.status.read',
  'system.config.read',
  'system.config.write',
  'system.users.read',
  'system.users.write',
  'system.reboot',
  'diagnostics.read',
  'diagnostics.exec',
] as const;

export type Privilege = (typeof PRIVILEGES)[number] | '*';

export interface Role {
  id: string;
  name: string;
  description: string;
  privileges: Privilege[];
}

export const DEFAULT_ROLES: Record<string, Role> = {
  admin: {
    id: 'admin',
    name: 'Administrator',
    description: 'Full unconstrained administrative access',
    privileges: ['*'],
  },
  operator: {
    id: 'operator',
    name: 'Network Operator',
    description: 'Can manage firewall rules, aliases, VPNs, and execute network diagnostics',
    privileges: [
      'firewall.rules.read',
      'firewall.rules.write',
      'firewall.aliases.read',
      'firewall.aliases.write',
      'firewall.nat.read',
      'firewall.nat.write',
      'interfaces.read',
      'routing.read',
      'services.dhcp.read',
      'services.dns.read',
      'vpn.wireguard.read',
      'vpn.wireguard.write',
      'system.status.read',
      'system.config.read',
      'diagnostics.read',
      'diagnostics.exec',
    ],
  },
  readonly: {
    id: 'readonly',
    name: 'Read Only Auditor',
    description: 'Can inspect firewall configuration, logs, and status without making changes',
    privileges: [
      'firewall.rules.read',
      'firewall.aliases.read',
      'firewall.nat.read',
      'interfaces.read',
      'routing.read',
      'services.dhcp.read',
      'services.dns.read',
      'vpn.wireguard.read',
      'system.status.read',
      'system.config.read',
      'diagnostics.read',
    ],
  },
};

export function hasPrivilege(userPrivileges: Privilege[], requiredPrivilege: Privilege): boolean {
  if (userPrivileges.includes('*')) return true;
  return userPrivileges.includes(requiredPrivilege);
}

export interface UserSession {
  userId: string;
  username: string;
  displayName?: string;
  email?: string;
  source: 'ldap' | 'local_admin';
  roles: string[];
  privileges: Privilege[];
  exp: number;
  /** True while the local admin still uses the never-changed default
   *  password; carried into the session JWT as pwd_change_required. */
  passwordChangeRequired?: boolean;
}
