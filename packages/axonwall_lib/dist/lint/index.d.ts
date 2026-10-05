import type { DesiredState } from '../schemas/index.js';
export interface LintIssue {
    type: 'shadowed_rule' | 'duplicate_rule' | 'unused_alias' | 'missing_interface';
    severity: 'error' | 'warning' | 'info';
    message: string;
    ruleId?: string;
    aliasName?: string;
}
export declare function lintRuleset(state: DesiredState): LintIssue[];
//# sourceMappingURL=index.d.ts.map