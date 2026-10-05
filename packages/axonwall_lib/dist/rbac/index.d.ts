/**
 * Axonwall RBAC (Role-Based Access Control)
 * Granular privileges matching and modernizing OPNsense page permissions.
 */
export declare const PRIVILEGES: readonly ["firewall.rules.read", "firewall.rules.write", "firewall.aliases.read", "firewall.aliases.write", "firewall.nat.read", "firewall.nat.write", "interfaces.read", "interfaces.write", "routing.read", "routing.write", "services.dhcp.read", "services.dhcp.write", "services.dns.read", "services.dns.write", "vpn.wireguard.read", "vpn.wireguard.write", "system.status.read", "system.config.read", "system.config.write", "system.users.read", "system.users.write", "system.reboot", "diagnostics.read", "diagnostics.exec"];
export type Privilege = (typeof PRIVILEGES)[number] | '*';
export interface Role {
    id: string;
    name: string;
    description: string;
    privileges: Privilege[];
}
export declare const DEFAULT_ROLES: Record<string, Role>;
export declare function hasPrivilege(userPrivileges: Privilege[], requiredPrivilege: Privilege): boolean;
export interface UserSession {
    userId: string;
    username: string;
    displayName?: string;
    email?: string;
    source: 'ldap' | 'local_admin';
    roles: string[];
    privileges: Privilege[];
    exp: number;
}
//# sourceMappingURL=index.d.ts.map