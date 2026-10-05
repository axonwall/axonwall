import type { DesiredState } from '../../schemas/index.js';
export interface CompileResult {
    nftScript: string;
    warnings: string[];
}
export declare function compileNftables(state: DesiredState): CompileResult;
//# sourceMappingURL=index.d.ts.map