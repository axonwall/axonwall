<!-- BEGIN:turborepo-agent-rules -->

# This is NOT the Turborepo you know

Turborepo configuration, task behavior, and CLI commands can vary between installed versions and may differ from your training data. Resolve the `turbo` package from this file's directory or relevant workspace; in monorepos, it may not be visible from the repository root. For example, run `node -p "require.resolve('turbo/package.json')"` from a workspace that depends on `turbo`.

Read `docs/README.md` inside that installed package first, then read the relevant pages from its `docs/` directory before changing Turborepo configuration or commands. Heed deprecation notices. These bundled docs match the installed package version and are available without network access.

This block is written and re-added by `turbo` before repository-scoped commands when an AI agent is detected. In the Turborepo source repository, its template is defined in `crates/turborepo-cli/src/cli/agent_guidance.rs`. Removing the managed block while updates are enabled means a later qualifying invocation will add it again. Set `"agentGuidance": false` in the root `turbo.json` or `turbo.jsonc` to opt out; this does not remove an existing block. Keep the block committed with your work to avoid an uncommitted change on the next agent invocation.
<!-- END:turborepo-agent-rules -->

## Releases & `axonwall.com` Submodule

Always update and push the `axonwall.com/` git submodule whenever releasing a new tag (`vX.Y.Z`).

- **Single source of truth**: `axonwall.com/src/data/releases.json` (`releases[0]` drives `RELEASE_VERSION`, `RELEASE_TAG`, `RELEASE_DATE`, asset download URLs, and the active changelog entry exported by `axonwall.com/src/lib/release.ts` via `@/lib/release`). Import from `@/lib/release` rather than hardcoding current version strings or dates in components or docs.
- **Release workflow**:
  1. Update feature documentation in `axonwall.com/src/app/docs/` if user-facing docs changed.
  2. Prepare or pass release highlights for `X.Y.Z` using `axonwall.com/src/data/releases.json` directly, `--notes-file <file.md>`, `--highlight "<bullet>"`, or `--edit-notes` (omitting notes flags drafts highlights automatically from `git log` commits since the previous tag).
  3. Run `./scripts/release-tagger.sh <patch|minor|major|X.Y.Z> --push` — it syncs `axonwall.com` via `scripts/sync-website-release.mjs`, typechecks `axonwall.com`, commits and pushes `axonwall.com` first, then commits the updated `axonwall.com` gitlink and pushes `main` + tag `vX.Y.Z`.
- **Completion criteria**: `axonwall.com` has a pushed commit on `origin/main` whose `src/data/releases.json[0].version` matches `X.Y.Z`, the parent release commit records that `axonwall.com` gitlink, and tag `vX.Y.Z` is pushed to `origin`.

