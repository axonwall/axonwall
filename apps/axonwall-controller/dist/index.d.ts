import { type DesiredState } from '@axonwall/lib/schemas';
export interface CompiledBundle {
    jobId: string;
    bundleHash: string;
    nftScript: string;
    files: {
        path: string;
        content: string;
        fileMode: number;
    }[];
    reloadServices: string[];
    warnings: string[];
    generatedAt: string;
}
export declare function buildArtifactBundle(jobId: string, state: DesiredState): CompiledBundle;
import * as http from 'node:http';
import * as https from 'node:https';
import * as net from 'node:net';
import { authenticateMcpToken, createMcpApiKeyRecord, listMcpApiKeys, revokeMcpApiKeyRecord } from './mcp/authz.js';
import { processMcpJsonRpcMessage, MCP_RESOURCES_CATALOG, MCP_TOOLS_CATALOG, newMcpApplyJobId, insertMcpRuleIntoState, desiredStateLockPath } from './mcp/server.js';
import { acquireMcpLockFile } from './mcp/lockfile.js';
import { recordMcpAuditEntry, verifyMcpAuditChain, queryMcpAuditEntries } from './mcp/audit.js';
import { isMcpServerEnabled, getMcpServerStatus } from '@axonwall/lib/mcp';
export interface ControllerTlsConfig {
    cert: Buffer | string;
    key: Buffer | string;
    ca?: Buffer | string;
    isFallback?: boolean;
}
export declare function ensureControllerTls(certPath?: string, keyPath?: string, caPath?: string, caKeyPath?: string): ControllerTlsConfig | null;
export { authenticateMcpToken, createMcpApiKeyRecord, listMcpApiKeys, revokeMcpApiKeyRecord, processMcpJsonRpcMessage, MCP_RESOURCES_CATALOG, MCP_TOOLS_CATALOG, newMcpApplyJobId, insertMcpRuleIntoState, desiredStateLockPath, acquireMcpLockFile, recordMcpAuditEntry, verifyMcpAuditChain, queryMcpAuditEntries, isMcpServerEnabled, getMcpServerStatus, };
export declare function isValidMacAddress(value: unknown): boolean;
export declare function normalizeMacAddress(value: string): string;
export declare function isValidCidr(value: unknown): boolean;
export interface HaTransitionRequest {
    role?: unknown;
    state?: unknown;
    type?: unknown;
    satelliteId?: unknown;
    sharedWanMac?: unknown;
    lanVip?: unknown;
}
export interface HaTransitionValidation {
    ok: boolean;
    error?: string;
    status?: number;
    transition?: 'PROMOTE' | 'DEMOTE';
    role?: 'active' | 'standby';
    satelliteId?: string;
    sharedWanMac?: string;
    lanVip?: string;
}
export type FleetSyncBodyValidation = {
    ok: true;
    desired: DesiredState | undefined;
} | {
    ok: false;
    status: 400;
    error: string;
};
export declare function parseFleetSyncBody(body: string): FleetSyncBodyValidation;
export declare function secureTokenEquals(presented: unknown, expected: unknown): boolean;
export declare function validateHaTransition(payload: HaTransitionRequest, fleetLanVip?: string): HaTransitionValidation;
export interface PersistedHaState {
    activeHaEdgeId: string | null;
    sharedWanMac?: string;
    lanVip?: string;
}
export declare function loadPersistedHaState(): PersistedHaState | null;
export declare function persistHaState(state: PersistedHaState): void;
export declare const MESH_DISCONNECTED_GRACE_MS: number;
export declare const SATELLITE_HEARTBEAT_MS: number;
export declare const SATELLITE_LAST_SEEN_GRACE_MS: number;
export declare function shouldPruneDisconnectedSatellite(disconnectedAt: string | undefined, nowMs: number, graceMs?: number): boolean;
export declare const PENDING_COMMAND_STALE_MS: number;
export interface SatelliteCommandAck {
    command: string;
    commandId?: string;
    success: boolean;
    error?: string;
}
export declare function buildSatelliteCommandEnvelope(type: string, payload: unknown, commandId: string): string;
export declare function isPendingCommandStale(sentAtMs: number, nowMs: number, staleMs?: number): boolean;
export declare function recordCommandAck(state: {
    lastApplyError?: string;
}, ack: SatelliteCommandAck): void;
export declare function headscaleRetryDelaysMs(): number[];
export declare const HEADSCALE_RECHECK_MS: number;
export interface HeadscaleProvisionDeps {
    listUsers: () => Promise<any[]>;
    createUser: (name: string) => Promise<any>;
    createPreAuthKey: (user: string, reusable: boolean, ephemeral: boolean, expiration: string) => Promise<{
        key: string;
    }>;
    serverUrl: string;
    send: (msg: unknown) => void;
    isOpen: () => boolean;
    sleep?: (ms: number) => Promise<void>;
    delaysMs?: number[];
}
export declare function provisionHeadscaleWithRetry(deps: HeadscaleProvisionDeps): Promise<boolean>;
export declare function deriveSatelliteRole(input: {
    configuredRole?: 'satellite' | 'edge-ngfw' | null;
    currentRole?: 'satellite' | 'edge-ngfw' | null;
    satelliteId: string;
    pid1ModeReported?: boolean;
}): 'satellite' | 'edge-ngfw';
export declare function createHttpRedirectServer(targetPort: number): http.Server;
export declare function createPortMultiplexer(httpsServer: https.Server, redirectServer: http.Server, opts?: {
    handshakeTimeoutMs?: number;
}): net.Server;
//# sourceMappingURL=index.d.ts.map