import type { DesiredState } from '@axonwall/lib/schemas';
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
import { processMcpJsonRpcMessage, MCP_RESOURCES_CATALOG, MCP_TOOLS_CATALOG } from './mcp/server.js';
import { recordMcpAuditEntry, verifyMcpAuditChain, queryMcpAuditEntries } from './mcp/audit.js';
export { authenticateMcpToken, createMcpApiKeyRecord, listMcpApiKeys, revokeMcpApiKeyRecord, processMcpJsonRpcMessage, MCP_RESOURCES_CATALOG, MCP_TOOLS_CATALOG, recordMcpAuditEntry, verifyMcpAuditChain, queryMcpAuditEntries, };
export declare function createHttpRedirectServer(targetPort: number): http.Server;
export declare function createPortMultiplexer(httpsServer: https.Server, redirectServer: http.Server): net.Server;
//# sourceMappingURL=index.d.ts.map