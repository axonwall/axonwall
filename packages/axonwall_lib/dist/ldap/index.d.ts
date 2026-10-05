import { type UserSession } from '../rbac/index.js';
export interface LdapConfig {
    url: string;
    baseDn: string;
    bindDn?: string;
    bindPassword?: string;
    userSearchFilter: string;
    groupSearchFilter: string;
    groupRoleMap?: Record<string, string>;
    timeoutMs?: number;
}
export interface AuthResult {
    success: boolean;
    error?: string;
    session?: UserSession;
}
export declare function authenticateLdap(config: LdapConfig, username: string, password: string): Promise<AuthResult>;
/**
 * Break-glass local admin verification for emergency console or initial bootstrap
 */
export declare function authenticateLocalAdmin(username: string, pass: string, expectedUser: string, expectedPassHash: string): AuthResult;
/**
 * Mints a Supabase-compatible JWT
 */
export declare function mintSupabaseToken(session: UserSession, jwtSecret: string): Promise<string>;
/**
 * Verify and decode JWT
 */
export declare function verifyToken(token: string, jwtSecret: string): Promise<UserSession | null>;
//# sourceMappingURL=index.d.ts.map