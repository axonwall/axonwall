#!/usr/bin/env node
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEFAULT_REPO_ROOT = path.resolve(__dirname, '..');

const SEMVER_RE = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/;
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

const TYPE_TO_TAG = {
  patch: 'Patch Release',
  minor: 'Feature Release',
  major: 'Major Release',
};

function printHelp() {
  console.log(`Usage: sync-website-release.mjs --version <X.Y.Z> [options]

Options:
  --version <X.Y.Z>    Target release version (required; leading 'v' stripped)
  --date <YYYY-MM-DD>  Release date (default: local today for new entries)
  --type <patch|minor|major>
                       Release type used for default tag badge (default: patch)
  --tag <label>        Explicit tag label override (e.g. "Security Release")
  -n, --notes-file <path>
                       Read highlight bullets from a Markdown/plain-text file
  --highlight <text>   Add a highlight bullet (repeatable)
  --edit               Open $VISUAL/$EDITOR to compose or refine release notes
  --from-git           Force drafting highlights from git commits since last tag
  --site-dir <path>    Path to axonwall.com repo (default: <repo>/axonwall.com)
  --repo-dir <path>    Path to parent axonwall git repo (default: <repo>)
  --dry-run            Print the resolved entry without modifying files
  -h, --help           Show this help message
`);
}

function localTodayIso() {
  const now = new Date();
  const y = now.getFullYear();
  const m = String(now.getMonth() + 1).padStart(2, '0');
  const d = String(now.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

function parseArgs(argv) {
  const opts = {
    version: '',
    date: '',
    type: 'patch',
    tag: '',
    notesFile: '',
    highlights: [],
    edit: false,
    fromGit: false,
    siteDir: '',
    repoDir: DEFAULT_REPO_ROOT,
    dryRun: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '-h' || arg === '--help') {
      printHelp();
      process.exit(0);
    } else if (arg === '--version') {
      opts.version = argv[++i] ?? '';
    } else if (arg === '--date') {
      opts.date = argv[++i] ?? '';
    } else if (arg === '--type') {
      opts.type = (argv[++i] ?? '').toLowerCase();
    } else if (arg === '--tag') {
      opts.tag = argv[++i] ?? '';
    } else if (arg === '--notes-file' || arg === '-n') {
      opts.notesFile = argv[++i] ?? '';
    } else if (arg === '--highlight') {
      const val = argv[++i];
      if (val === undefined) {
        throw new Error('--highlight requires a value');
      }
      if (val.trim()) opts.highlights.push(val.trim());
    } else if (arg === '--edit') {
      opts.edit = true;
    } else if (arg === '--from-git') {
      opts.fromGit = true;
    } else if (arg === '--site-dir') {
      opts.siteDir = argv[++i] ?? '';
    } else if (arg === '--repo-dir') {
      opts.repoDir = path.resolve(argv[++i] ?? '.');
    } else if (arg === '--dry-run') {
      opts.dryRun = true;
    } else {
      throw new Error(`Unknown option: ${arg}`);
    }
  }

  if (!opts.siteDir) {
    opts.siteDir = path.join(opts.repoDir, 'axonwall.com');
  } else {
    opts.siteDir = path.resolve(opts.siteDir);
  }

  opts.version = opts.version.trim().replace(/^v/, '');
  if (!SEMVER_RE.test(opts.version)) {
    throw new Error(`Invalid or missing --version "${opts.version}" (expected X.Y.Z semver)`);
  }

  if (opts.date && !ISO_DATE_RE.test(opts.date)) {
    throw new Error(`Invalid --date "${opts.date}" (expected YYYY-MM-DD)`);
  }

  if (opts.type && !TYPE_TO_TAG[opts.type]) {
    throw new Error(`Invalid --type "${opts.type}" (expected patch, minor, or major)`);
  }

  return opts;
}

/**
 * Parse Markdown or plain-text bullet notes into flat highlight paragraphs.
 * Blank lines and `#` heading/comment lines are ignored; indented lines continue
 * the active bullet.
 */
function parseNotesText(raw) {
  const bullets = [];
  for (const rawLine of raw.split(/\r?\n/)) {
    const trimmedRight = rawLine.trimEnd();
    const trimmed = trimmedRight.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }
    const bulletMatch = /^([-*•]|\d+[.)])\s+(.*)$/.exec(trimmed);
    if (bulletMatch) {
      const body = bulletMatch[2].trim();
      if (body) bullets.push(body);
    } else if (/^\s+/.test(rawLine) && bullets.length > 0) {
      bullets[bullets.length - 1] = `${bullets[bullets.length - 1]} ${trimmed}`;
    } else {
      bullets.push(trimmed);
    }
  }
  return bullets;
}

/**
 * Draft release highlights from commits in <latestTag>..HEAD (excluding chore(release): commits).
 */
function draftFromGit(repoDir, version) {
  let range = 'HEAD';
  try {
    const lastTag = execFileSync('git', ['-C', repoDir, 'describe', '--tags', '--abbrev=0'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    if (lastTag) {
      range = `${lastTag}..HEAD`;
    }
  } catch {
    // No reachable tags; inspect recent commits
  }

  let subjects = [];
  try {
    const out = execFileSync(
      'git',
      ['-C', repoDir, 'log', range, '--no-merges', '--max-count=20', '--pretty=format:%s'],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }
    ).trim();
    if (out) {
      subjects = out
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter((s) => s && !/^chore\(release\):/i.test(s));
    }
  } catch {
    // Not a git repo or no commits
  }

  if (subjects.length === 0) {
    return [`Maintenance and stability updates for v${version}.`];
  }
  return subjects;
}

/**
 * Launch $VISUAL/$EDITOR with a clean Markdown bullet template and return parsed highlights.
 */
function editHighlightsInEditor(version, initialHighlights) {
  const editorCmd = (process.env.VISUAL || process.env.EDITOR || 'vi').trim();
  const [cmd, ...cmdArgs] = editorCmd.split(/\s+/);
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-notes-'));
  const tmpFile = path.join(tmpDir, `v${version}-release-notes.md`);
  try {
    const lines = [
      `# Release notes for v${version}`,
      '# Lines starting with # are ignored. One bullet (-) per changelog highlight.',
      '# Leave empty (or delete all bullets) to abort.',
      '',
      ...initialHighlights.map((h) => `- ${h}`),
      '',
    ];
    fs.writeFileSync(tmpFile, lines.join('\n'), 'utf8');
    const res = spawnSync(cmd, [...cmdArgs, tmpFile], { stdio: 'inherit' });
    if (res.error) {
      throw new Error(`Failed to launch editor "${editorCmd}": ${res.error.message}`);
    }
    if (res.status !== 0) {
      throw new Error(`Editor exited with status ${res.status}`);
    }
    const edited = parseNotesText(fs.readFileSync(tmpFile, 'utf8'));
    if (edited.length === 0) {
      throw new Error('Release notes left empty in editor; aborting.');
    }
    return edited;
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function updateSitePackageJson(siteDir, version, dryRun) {
  const pkgPath = path.join(siteDir, 'package.json');
  if (!fs.existsSync(pkgPath)) return false;
  const raw = fs.readFileSync(pkgPath, 'utf8');
  const json = JSON.parse(raw);
  if (json.version === version) return false;
  json.version = version;
  if (!dryRun) {
    fs.writeFileSync(pkgPath, JSON.stringify(json, null, 2) + '\n', 'utf8');
  }
  return true;
}

function updateSiteReadme(siteDir, version, dryRun) {
  const readmePath = path.join(siteDir, 'README.md');
  if (!fs.existsSync(readmePath)) return false;
  const raw = fs.readFileSync(readmePath, 'utf8');
  let next = raw
    .replace(/(`v)\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(`\))/g, `$1${version}$3`)
    .replace(/(`v)\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(`\s+release portal)/g, `$1${version}$3`)
    .replace(/(#\s+v)\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\s+artifacts)/g, `$1${version}$3`);
  if (next === raw) return false;
  if (!dryRun) {
    fs.writeFileSync(readmePath, next, 'utf8');
  }
  return true;
}

function updateSiteOgImage(siteDir, version, dryRun) {
  const svgPath = path.join(siteDir, 'public', 'og-image.svg');
  if (!fs.existsSync(svgPath)) return false;
  const raw = fs.readFileSync(svgPath, 'utf8');
  const next = raw.replace(/>v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?<\/text>/g, `>v${version}</text>`);
  if (next === raw) return false;
  if (!dryRun) {
    fs.writeFileSync(svgPath, next, 'utf8');
  }
  return true;
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  const releasesPath = path.join(opts.siteDir, 'src', 'data', 'releases.json');
  if (!fs.existsSync(releasesPath)) {
    throw new Error(`Missing releases data file: ${releasesPath}`);
  }

  const releases = JSON.parse(fs.readFileSync(releasesPath, 'utf8'));
  if (!Array.isArray(releases)) {
    throw new Error(`${releasesPath} must contain a JSON array`);
  }

  const existingIdx = releases.findIndex(
    (entry) => String(entry.version ?? '').trim().replace(/^v/, '') === opts.version
  );
  const existing = existingIdx >= 0 ? releases[existingIdx] : null;

  let explicitHighlights = [];
  if (opts.notesFile) {
    if (!fs.existsSync(opts.notesFile)) {
      throw new Error(`Notes file not found: ${opts.notesFile}`);
    }
    explicitHighlights.push(...parseNotesText(fs.readFileSync(opts.notesFile, 'utf8')));
  }
  if (opts.highlights.length > 0) {
    explicitHighlights.push(...opts.highlights);
  }

  let highlights;
  if (explicitHighlights.length > 0) {
    highlights = explicitHighlights;
  } else if (opts.fromGit) {
    highlights = draftFromGit(opts.repoDir, opts.version);
  } else if (existing && Array.isArray(existing.highlights) && existing.highlights.length > 0) {
    highlights = [...existing.highlights];
  } else {
    highlights = draftFromGit(opts.repoDir, opts.version);
  }

  if (opts.edit) {
    highlights = editHighlightsInEditor(opts.version, highlights);
  }

  if (!highlights || highlights.length === 0) {
    throw new Error('Cannot record a release entry with empty highlights.');
  }

  const resolvedEntry = {
    version: opts.version,
    date: opts.date || existing?.date || localTodayIso(),
    tag: opts.tag || existing?.tag || TYPE_TO_TAG[opts.type],
    highlights,
  };

  let nextReleases;
  if (existingIdx === 0) {
    nextReleases = [resolvedEntry, ...releases.slice(1)];
  } else if (existingIdx > 0) {
    nextReleases = [
      resolvedEntry,
      ...releases.slice(0, existingIdx),
      ...releases.slice(existingIdx + 1),
    ];
  } else {
    nextReleases = [resolvedEntry, ...releases];
  }

  const nextReleasesRaw = JSON.stringify(nextReleases, null, 2) + '\n';
  const curReleasesRaw = fs.readFileSync(releasesPath, 'utf8');
  const releasesChanged = nextReleasesRaw !== curReleasesRaw;

  if (!opts.dryRun && releasesChanged) {
    fs.writeFileSync(releasesPath, nextReleasesRaw, 'utf8');
  }

  const pkgChanged = updateSitePackageJson(opts.siteDir, opts.version, opts.dryRun);
  const readmeChanged = updateSiteReadme(opts.siteDir, opts.version, opts.dryRun);
  const ogChanged = updateSiteOgImage(opts.siteDir, opts.version, opts.dryRun);

  if (opts.dryRun) {
    console.log('[dry-run] Resolved release entry:');
    console.log(JSON.stringify(resolvedEntry, null, 2));
    console.log(
      `[dry-run] Would update: releases.json=${releasesChanged} package.json=${pkgChanged} README.md=${readmeChanged} og-image.svg=${ogChanged}`
    );
  } else {
    console.log(
      `[✓] Synced ${opts.siteDir} for v${opts.version} (releases.json=${releasesChanged}, package.json=${pkgChanged}, README.md=${readmeChanged}, og-image.svg=${ogChanged})`
    );
  }
}

try {
  main();
} catch (err) {
  console.error(`[!] sync-website-release error: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}
