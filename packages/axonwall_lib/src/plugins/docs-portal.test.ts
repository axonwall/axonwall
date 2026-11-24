import { describe, it, expect } from 'vitest';
import { DesiredStateSchema } from '../schemas/index.js';
import {
  BUILTIN_PLUGINS,
  findPluginById,
  isPluginEnabled,
  enablePluginWithDependencies,
  disablePluginWithDependents,
} from './index.js';

describe('Offline Documentation Portal (docs-portal) plugin', () => {
  it('registers docs-portal as an opt-in extension with zero OS packages', () => {
    const manifest = BUILTIN_PLUGINS.find((p) => p.id === 'docs-portal');
    expect(manifest).toBeDefined();
    expect(findPluginById('docs-portal')).toEqual(manifest);
    expect(manifest?.category).toBe('extension');
    expect(manifest?.defaultEnabled).toBe(false);
    expect(manifest?.menuEntry?.path).toBe('/docs');
    expect(manifest?.packages).toBeUndefined();
  });

  it('defaults to disabled when state is null or DesiredState has no plugins entry', () => {
    expect(isPluginEnabled('docs-portal', null)).toBe(false);
    expect(isPluginEnabled('docs-portal', undefined)).toBe(false);
    const defaultState = DesiredStateSchema.parse({});
    expect(isPluginEnabled('docs-portal', defaultState)).toBe(false);
  });

  it('enables and disables docs-portal cleanly via dependency helpers', () => {
    const baseState = DesiredStateSchema.parse({});
    const enabled = enablePluginWithDependencies('docs-portal', baseState);
    expect(enabled.autoEnabledDependencies).toEqual([]);
    expect(isPluginEnabled('docs-portal', enabled.state)).toBe(true);

    const disabled = disablePluginWithDependents('docs-portal', enabled.state);
    expect(disabled.autoDisabledDependents).toEqual([]);
    expect(isPluginEnabled('docs-portal', disabled.state)).toBe(false);
  });
});
