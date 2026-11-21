import { describe, it, expect } from 'vitest';
import {
  PluginBundledArchiveBinarySchema,
  PluginBundledBinarySchema,
  PluginBundledDistroPackageBinarySchema,
  PluginBundledRawBinarySchema,
  PluginBinDirSchema,
  PluginEnvSchema,
  PluginManifestSchema,
} from './index.js';

// Plugin-bundled binaries: schema-level proofs for the manifest
// rules (W5). These mirror the daemon-side validation table in
// apps/axonwalld/engine/plugin_bundled_binaries_test.go — but the
// two layers deliberately do NOT enforce the same set:
//
//   - The zod schema ACCEPTS the temporary `SHA256_TODO_<name>`
//     markers (a manifest under construction still parses); the
//     DAEMON rejects them at install time (fail closed). Both
//     halves are asserted here (accept) and in Go (reject).
//   - The archive/distroPackage schemas are NOT strict: zod strips
//     unknown keys, so an archive entry carrying distro fields
//     still parses here (fields silently dropped) and is the
//     DAEMON's validation that rejects it. Only the raw-binary
//     schema is `.strict()` and rejects meaningless fields itself.
//
// NOTE: zod v4 stringifies a ZodError's message as JSON, so the
// refine messages' quotes come back backslash-escaped
// (extract \"tree\"); the toThrow regexes below match only the
// unquoted prefix for that reason.

const HEX64 = 'a'.repeat(64);

const validArchive = {
  kind: 'archive',
  name: 'rosenpass',
  url: 'https://github.com/rosenpass/rosenpass/releases/download/v0.2.3/rosenpass-x86_64-linux-0.2.3.tar',
  sha256: HEX64,
  format: 'tar',
  pathInArchive: 'bin/rosenpass',
} as const;

const validRaw = {
  kind: 'binary',
  name: 'k3s',
  url: 'https://github.com/k3s-io/k3s/releases/download/v1.32.3%2Bk3s1/k3s',
  sha256: HEX64,
} as const;

const validDistro = {
  kind: 'distroPackage',
  name: 'emacs-nox',
  sha256: HEX64,
  distro: 'debian',
  package: 'emacs-nox',
  source: 'emacs',
  version: '1:30.1+1-6+deb13u1',
  arch: 'amd64',
} as const;

describe('PluginBundledBinarySchema (bundled binaries)', () => {
  it('parses a valid archive entry', () => {
    expect(PluginBundledBinarySchema.parse(validArchive)).toMatchObject({
      kind: 'archive',
      name: 'rosenpass',
    });
  });

  it('parses a valid raw-binary entry', () => {
    expect(PluginBundledBinarySchema.parse(validRaw)).toMatchObject({
      kind: 'binary',
      name: 'k3s',
    });
  });

  it('parses a valid distroPackage entry', () => {
    expect(PluginBundledBinarySchema.parse(validDistro)).toMatchObject({
      kind: 'distroPackage',
      name: 'emacs-nox',
      source: 'emacs',
    });
  });

  it('rejects a short sha256', () => {
    expect(() =>
      PluginBundledBinarySchema.parse({ ...validArchive, sha256: 'abc' }),
    ).toThrow(/sha256 must be a 64-char hex digest/);
  });

  it('rejects a non-hex sha256', () => {
    expect(() =>
      PluginBundledBinarySchema.parse({ ...validArchive, sha256: 'z'.repeat(64) }),
    ).toThrow(/sha256 must be a 64-char hex digest/);
  });

  it('rejects a missing sha256 (never optional)', () => {
    const { kind, name, url, format, pathInArchive } = validArchive;
    expect(() =>
      PluginBundledBinarySchema.parse({ kind, name, url, format, pathInArchive }),
    ).toThrow();
  });

  it('ACCEPTS a SHA256_TODO_ marker at schema level (the daemon rejects it at install)', () => {
    const parsed = PluginBundledBinarySchema.parse({
      ...validArchive,
      sha256: 'SHA256_TODO_rosenpass',
    });
    expect(parsed.sha256).toBe('SHA256_TODO_rosenpass');
  });

  it('rejects an unknown kind', () => {
    expect(() =>
      PluginBundledBinarySchema.parse({ ...validArchive, kind: 'tarball' }),
    ).toThrow();
  });

  it('rejects a non-http(s) archive url', () => {
    expect(() =>
      PluginBundledBinarySchema.parse({ ...validArchive, url: 'ftp://example.com/tool.tar' }),
    ).toThrow(/archive url must be an http\(s\) URL/);
  });

  it('rejects an unknown archive format', () => {
    expect(() =>
      PluginBundledBinarySchema.parse({ ...validArchive, format: 'rar' }),
    ).toThrow();
  });

  it('rejects tree extraction combined with pathInArchive', () => {
    expect(() =>
      PluginBundledArchiveBinarySchema.parse({
        ...validArchive,
        extract: 'tree',
        pathInArchive: 'bin/rosenpass',
      }),
    ).toThrow(/pathInArchive must be omitted with extract/);
  });

  it('rejects stripComponents without tree extraction', () => {
    expect(() =>
      PluginBundledArchiveBinarySchema.parse({
        ...validArchive,
        stripComponents: 1,
      }),
    ).toThrow(/stripComponents is only meaningful with extract/);
  });

  it('accepts tree extraction with stripComponents', () => {
    expect(
      PluginBundledArchiveBinarySchema.parse({
        ...validArchive,
        extract: 'tree',
        stripComponents: 1,
        pathInArchive: undefined,
      }),
    ).toMatchObject({ extract: 'tree', stripComponents: 1 });
  });

  it('rejects stripComponents above 8', () => {
    expect(() =>
      PluginBundledArchiveBinarySchema.parse({
        ...validArchive,
        extract: 'tree',
        stripComponents: 9,
      }),
    ).toThrow();
  });

  it('rejects an unknown oses family', () => {
    expect(() =>
      PluginBundledArchiveBinarySchema.parse({ ...validArchive, oses: ['windows'] }),
    ).toThrow();
  });

  it('accepts a debian oses gate', () => {
    expect(
      PluginBundledArchiveBinarySchema.parse({ ...validArchive, oses: ['debian'] }),
    ).toMatchObject({ oses: ['debian'] });
  });

  it('documents that archive entries strip (not reject) distro fields — the daemon rejects them', () => {
    // zod objects strip unknown keys by default; the archive schema
    // relies on the daemon's validateBundledBinaries for this check
    // (see the Go validation table). Assert the strip so a future
    // strict-ification shows up here as a failure, not silently.
    const parsed = PluginBundledArchiveBinarySchema.parse({
      ...validArchive,
      distro: 'debian',
      package: 'rosenpass',
    });
    expect(parsed).not.toHaveProperty('distro');
    expect(parsed).not.toHaveProperty('package');
  });

  it('rejects meaningless fields on a raw binary (strict schema)', () => {
    expect(() =>
      PluginBundledRawBinarySchema.parse({ ...validRaw, format: 'tar' }),
    ).toThrow();
    expect(() =>
      PluginBundledRawBinarySchema.parse({ ...validRaw, pathInArchive: 'k3s' }),
    ).toThrow();
    expect(() =>
      PluginBundledRawBinarySchema.parse({ ...validRaw, distro: 'debian' }),
    ).toThrow();
  });

  it('documents that a distroPackage entry strips (not rejects) a url field — the daemon rejects it', () => {
    expect(() =>
      PluginBundledDistroPackageBinarySchema.parse({
        ...validDistro,
        url: 'https://example.com/tool.deb',
      }),
    ).not.toThrow(); // schema strips the unknown key; the daemon rejects it
  });

  it('rejects a distroPackage entry missing version', () => {
    const { kind, name, sha256, distro, package: pkg, source, arch } = validDistro;
    expect(() =>
      PluginBundledDistroPackageBinarySchema.parse({
        kind,
        name,
        sha256,
        distro,
        package: pkg,
        source,
        arch,
      }),
    ).toThrow();
  });

  it('rejects a distroPackage entry for an unknown distro', () => {
    expect(() =>
      PluginBundledDistroPackageBinarySchema.parse({ ...validDistro, distro: 'windows' }),
    ).toThrow();
  });

  it('accepts oses gating on raw and distroPackage entries and rejects traversal', () => {
    expect(
      PluginBundledRawBinarySchema.parse({ ...validRaw, oses: ['debian'] }),
    ).toMatchObject({ oses: ['debian'] });
    expect(
      PluginBundledDistroPackageBinarySchema.parse({ ...validDistro, oses: ['debian'] }),
    ).toMatchObject({ oses: ['debian'] });
    expect(() =>
      PluginBundledArchiveBinarySchema.parse({ ...validArchive, name: '../evil' }),
    ).toThrow();
    expect(() =>
      PluginBundledArchiveBinarySchema.parse({ ...validArchive, pathInArchive: '../../etc/passwd' }),
    ).toThrow();
    expect(() =>
      PluginManifestSchema.parse({
        id: '../escape',
        name: 'Bad',
        version: '1.0.0',
      }),
    ).toThrow();
  });
});

describe('PluginBinDirSchema', () => {
  it('accepts relative bin dirs', () => {
    expect(PluginBinDirSchema.parse('bin')).toBe('bin');
    expect(PluginBinDirSchema.parse('usr/bin')).toBe('usr/bin');
  });

  it('rejects absolute, dotdot, empty-segment and backslash entries', () => {
    for (const bad of ['/bin', '../up', 'a//b', 'a\\b', '']) {
      expect(() => PluginBinDirSchema.parse(bad), `binDir ${JSON.stringify(bad)}`).toThrow();
    }
  });
});

describe('PluginEnvSchema', () => {
  it('accepts valid env keys and ${PLUGIN_DIR} values', () => {
    expect(
      PluginEnvSchema.parse({ EMACSDATA: '${PLUGIN_DIR}/usr/share/emacs/30.1/etc' }),
    ).toEqual({ EMACSDATA: '${PLUGIN_DIR}/usr/share/emacs/30.1/etc' });
  });

  it('rejects invalid env keys', () => {
    for (const bad of ['1BAD', 'HAS-DASH', 'has space', '']) {
      expect(() => PluginEnvSchema.parse({ [bad]: 'x' }), `env key ${JSON.stringify(bad)}`).toThrow(
        /env keys must be valid environment variable names/,
      );
    }
  });
});

describe('PluginManifestSchema with bundled binaries', () => {
  const baseManifest = {
    id: 'cli-emacs',
    name: 'Emacs Editor',
    version: '0.1.0',
    binaries: [validDistro],
    binDirs: ['bin', 'usr/bin'],
    env: { EMACSDATA: '${PLUGIN_DIR}/usr/share/emacs/30.1/etc' },
  };

  it('parses a manifest carrying binaries, binDirs and env', () => {
    const parsed = PluginManifestSchema.parse(baseManifest);
    expect(parsed.binaries).toHaveLength(1);
    expect(parsed.binDirs).toEqual(['bin', 'usr/bin']);
    expect(parsed.env).toEqual({ EMACSDATA: '${PLUGIN_DIR}/usr/share/emacs/30.1/etc' });
  });

  it('accepts a TODO-marker sha256 in a manifest but rejects a malformed one', () => {
    expect(() =>
      PluginManifestSchema.parse({
        ...baseManifest,
        binaries: [{ ...validDistro, sha256: 'SHA256_TODO_emacs-nox' }],
      }),
    ).not.toThrow(); // TODO marker parses; the daemon refuses to install it
    expect(() =>
      PluginManifestSchema.parse({
        ...baseManifest,
        binaries: [{ ...validDistro, sha256: 'xyz' }],
      }),
    ).toThrow(/sha256 must be a 64-char hex digest/);
  });

  it('rejects a manifest with a bad binDir', () => {
    expect(() =>
      PluginManifestSchema.parse({ ...baseManifest, binDirs: ['../escape'] }),
    ).toThrow(/binDirs entries must be relative paths/);
  });

  it('rejects a manifest with a bad env key', () => {
    expect(() =>
      PluginManifestSchema.parse({ ...baseManifest, env: { 'BAD-KEY': 'x' } }),
    ).toThrow(/env keys must be valid environment variable names/);
  });
});
