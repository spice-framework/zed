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
- Fixture source remains valid Go and pins a canonical Spice version without a
  local `replace` directive.
- Dependencies are exact and locked. Add one only after maintenance, license,
  security, cancellation, and compatibility review.
- Keep the Zed presentation ceiling explicit: comment-prefix concealment is not
  available here.

Every commit must pass formatting, clippy with warnings denied, locked tests,
the release WASI build, and the offline Spice fixture verification. Work
directly on local `main` in bounded commits and fetch before push.
