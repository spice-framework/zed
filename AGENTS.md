# Spice Zed implementation contract

## Mission

Provide a small, honest Zed integration for Spice's shared language server.
Do not duplicate compiler semantics in Rust or promise editor presentation APIs
that Zed does not expose.

## Invariants

- Rust 1.93.0 and Go 1.26.5 are mandatory.
- The extension launches an existing `spice lsp`; it never downloads binaries,
  installs modules, or mutates application source.
- Diagnostics, completion, navigation, hover, and code actions remain owned by
  the canonical Spice compiler pipeline.
- Fixture source remains valid Go, retains canonical core descriptors/runtime,
  pins exact public core/toolchain versions, and contains no local replacement.
- Dependencies are exact and locked. Add one only after maintenance, license,
  security, cancellation, and compatibility review.
- Keep the Zed presentation ceiling explicit: comment-prefix concealment is not
  available here.

Every commit must pass formatting, clippy with warnings denied, locked tests,
the standard-library release-tool tests, the release WASI build, and the
offline Spice fixture verification. Work directly on local `main` in bounded
commits and fetch before push.

## Release security

- Release tags are exact `vMAJOR.MINOR.PATCH` values matching
  `extension.toml`, must resolve to `main`, and are immutable after creation.
- The only release signing key is the repository-specific Ed25519 private key
  held by the protected `release-signing` environment. Never write it to the
  repository, an artifact, a command line, or a log.
- `release-signing` and `release-publish` are separate approval boundaries and
  accept only `v*` tags. This repository currently has one maintainer, so the
  documented required reviewer uses `prevent_self_review=false`; the two
  sequential approvals still prevent an unattended tag from publishing.
- Only the final publish job may receive `contents: write`. Every earlier job
  is read-only and the signer never receives repository write authority.
- Release actions are pinned by full commit, the Windows rebuild receives no
  key, and publication is allowed only after signature and byte-reproducibility
  verification against the committed public anchor.
- Never create, move, or delete a release tag merely to exercise the workflow.
