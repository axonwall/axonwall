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
export declare function createHttpRedirectServer(targetPort: number): http.Server;
export declare function createPortMultiplexer(httpsServer: https.Server, redirectServer: http.Server): net.Server;
//# sourceMappingURL=index.d.ts.map