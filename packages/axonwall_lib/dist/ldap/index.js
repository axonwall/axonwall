import { Client } from 'ldapts';
import { SignJWT, jwtVerify } from 'jose';
import { DEFAULT_ROLES } from '../rbac/index.js';
export async function authenticateLdap(config, username, password) {
    if (!username || !password) {
        return { success: false, error: 'Username and password are required' };
    }
    const client = new Client({
        url: config.url,
        timeout: config.timeoutMs || 5000,
        connectTimeout: config.timeoutMs || 5000,
    });
    try {
        // 1. Initial bind as service account or anonymous
        if (config.bindDn && config.bindPassword) {
            await client.bind(config.bindDn, config.bindPassword);
        }
        // 2. Search for the user DN
        const filter = config.userSearchFilter.replace(/{{username}}/g, username);
        const searchRes = await client.search(config.baseDn, {
            filter,
            scope: 'sub',
            attributes: ['dn', 'cn', 'mail', 'memberOf'],
        });
        if (searchRes.searchEntries.length === 0) {
            return { success: false, error: 'User not found in LDAP directory' };
        }
        const userEntry = searchRes.searchEntries[0];
        const userDn = userEntry.dn;
        // 3. Authenticate by rebinding as the target user
        const userClient = new Client({
            url: config.url,
            timeout: config.timeoutMs || 5000,
        });
        try {
            await userClient.bind(userDn, password);
        }
        catch {
            return { success: false, error: 'Invalid credentials' };
        }
        finally {
            await userClient.unbind();
        }
        // 4. Resolve group memberships
        let groups = [];
        if (userEntry.memberOf) {
            const raw = Array.isArray(userEntry.memberOf) ? userEntry.memberOf : [userEntry.memberOf];
            groups = raw.map((g) => {
                // extract CN if full DN
                const match = /cn=([^,]+)/i.exec(String(g));
                return match ? match[1].toLowerCase() : String(g).toLowerCase();
            });
        }
        else {
            // Query groupOfNames by member
            const groupFilter = config.groupSearchFilter.replace(/{{userDn}}/g, userDn);
            const groupSearch = await client.search(config.baseDn, {
                filter: groupFilter,
                scope: 'sub',
                attributes: ['cn'],
            });
            groups = groupSearch.searchEntries.map((e) => String(e.cn).toLowerCase());
        }
        // 5. Map LDAP groups to Axonwall roles and privileges
        const roleMap = config.groupRoleMap || {
            admins: 'admin',
            operators: 'operator',
            readonly: 'readonly',
        };
        const roles = new Set();
        for (const g of groups) {
            if (roleMap[g]) {
                roles.add(roleMap[g]);
            }
        }
        // Default fallback to readonly if no roles matched
        if (roles.size === 0) {
            roles.add('readonly');
        }
        const privileges = new Set();
        for (const r of roles) {
            const roleDef = DEFAULT_ROLES[r];
            if (roleDef) {
                for (const p of roleDef.privileges) {
                    privileges.add(p);
                }
            }
        }
        const session = {
            userId: userDn,
            username,
            displayName: userEntry.cn || username,
            email: userEntry.mail || undefined,
            source: 'ldap',
            roles: Array.from(roles),
            privileges: Array.from(privileges),
            exp: Math.floor(Date.now() / 1000) + 8 * 3600, // 8 hours
        };
        return { success: true, session };
    }
    catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        return { success: false, error: `LDAP error: ${message}` };
    }
    finally {
        try {
            await client.unbind();
        }
        catch {
            // ignore
        }
    }
}
/**
 * Break-glass local admin verification for emergency console or initial bootstrap
 */
export function authenticateLocalAdmin(username, pass, expectedUser, expectedPassHash) {
    if (username === expectedUser && pass === expectedPassHash) {
        const adminRole = DEFAULT_ROLES.admin;
        return {
            success: true,
            session: {
                userId: 'local-admin-root',
                username: expectedUser,
                displayName: 'Emergency Local Administrator',
                source: 'local_admin',
                roles: ['admin'],
                privileges: [...adminRole.privileges],
                exp: Math.floor(Date.now() / 1000) + 4 * 3600,
            },
        };
    }
    return { success: false, error: 'Invalid local administrator credentials' };
}
/**
 * Mints a Supabase-compatible JWT
 */
export async function mintSupabaseToken(session, jwtSecret) {
    const secretKey = new TextEncoder().encode(jwtSecret);
    return new SignJWT({
        sub: session.userId,
        username: session.username,
        role: 'authenticated', // Supabase auth role for RLS
        app_roles: session.roles,
        app_privs: session.privileges,
        user_metadata: {
            displayName: session.displayName,
            email: session.email,
            source: session.source,
        },
    })
        .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
        .setIssuedAt()
        .setExpirationTime(session.exp)
        .sign(secretKey);
}
/**
 * Verify and decode JWT
 */
export async function verifyToken(token, jwtSecret) {
    try {
        const secretKey = new TextEncoder().encode(jwtSecret);
        const { payload } = await jwtVerify(token, secretKey);
        return {
            userId: payload.sub,
            username: payload.username || payload.sub,
            displayName: payload.user_metadata?.displayName,
            email: payload.user_metadata?.email,
            source: payload.user_metadata?.source || 'ldap',
            roles: payload.app_roles || [],
            privileges: payload.app_privs || [],
            exp: payload.exp || 0,
        };
    }
    catch {
        return null;
    }
}
