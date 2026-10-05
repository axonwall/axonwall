import type { DesiredState } from '@axonwall/lib/schemas';
export interface CompiledBundle {
    jobId: string;
    bundleHash: string;
    nftScript: string;
    warnings: string[];
    generatedAt: string;
}
export declare function buildArtifactBundle(jobId: string, state: DesiredState): CompiledBundle;
//# sourceMappingURL=index.d.ts.map