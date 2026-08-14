# Spice for Zed

Unified documentation: [spiceframework.dev/tools/zed](https://spiceframework.dev/tools/zed/).

This repository contains the independently versioned Zed extension for the
[Spice Framework](https://github.com/spice-framework/spice). It launches an
already installed `spice lsp` process and projects compiler-owned diagnostics,
completion, hover, navigation, and safe code actions into Go files.

## Honest presentation boundary

Spice annotations remain physical valid-Go comments such as
`// @Application`. Zed's extension API does not provide arbitrary zero-width
folding for comment prefixes, so this extension does not claim to conceal or
reclaim the width of `// `. GoLand owns the richer native presentation ceiling;
both editors consume the same Spice language-server behavior.

## Installation and configuration

Install a compatible `spice` executable on `PATH`, then install this extension
from a packaged release or as a Zed development extension. To use an explicit
binary, configure:

```json
{
  "lsp": {
    "spice": {
      "binary": {
        "path": "/absolute/path/to/spice",
        "arguments": ["lsp"]
      }
    }
  }
}
```

The extension never downloads modules, installs tools, or mutates `go.mod`.
Spice analysis retains its normal offline and explicit-tool authorization
rules.

## Projected workspace tasks

Zed's current extension API does not let an extension register arbitrary
project commands, and this extension augments the built-in Go language rather
than replacing its language extension. Copy
[`docs/spice-tasks.json`](docs/spice-tasks.json) to the project's
`.zed/tasks.json` to add these task-picker entries:

- `Spice: Open Projected Shell`
- `Spice: Open Codex in View`
- `Spice: Build`
- `Spice: Test`
- `Spice: Verify`

The shell and Codex tasks launch through `spice shell --retain`; build, test,
and verification launch through `spice exec`. All therefore use the same
materialized View workspace and command broker as the CLI and other editors.
The template does not create a Zed virtual workspace or claim to hide the
physical checkout from Zed itself.

## Compatibility and verification

Version `0.2.0` is pre-release software and is tested against Spice core
`v0.0.0-20260805222830-a2ecd56df246`, standalone toolchain
`v0.0.0-20260805230546-150f8ae62c13`, Go 1.26.5, Rust 1.93.0, and
`zed_extension_api` 0.7.0. The fixture uses that exact public module pair with
no local replacement. Hosted CI runs the locked Rust tests, deterministic
release-tool tests, WASI release build, and offline canonical Spice fixture on
Linux, Windows, and macOS. This is a
cross-platform extension/launcher proof; it does not claim installed-editor UI
automation that Zed's extension test surface does not expose.

Run the repository gate from the root:

```text
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
go -C release-tools test ./...
cargo build --locked --release --target wasm32-wasip2
cd fixture
go mod download
GOPROXY=off go tool github.com/spice-framework/toolchain/cmd/spice verify --format=json ./...
```

Core descriptors/runtime remain selected from the public canonical module.
The standalone toolchain is selected through its exact public pseudo-version;
the release gate rejects local replacements.

## Authenticated releases

An exact `vMAJOR.MINOR.PATCH` tag matching `extension.toml` starts a fail-closed
release pipeline. It builds and verifies the repository on Linux, independently
rebuilds the WASI extension on Windows, and requires the resulting package to
be byte-identical. The deterministic release contains exactly
`extension.toml`, `LICENSE`, and `extension.wasm`, accompanied by an SPDX 2.3
SBOM, in-toto/SLSA provenance, canonical SHA-256 checksums, the repository
Ed25519 public key, and a detached signature over those checksums.

Signing and publication use separate protected approvals. The private key is
available only to the signing job; only the final publishing job receives
`contents: write`, and it re-verifies downloaded GitHub assets before making a
pre-release public. Consumers should pin the committed trust anchor at
`security/release/ed25519-public.pem` and verify all six release assets with:

```text
go -C release-tools run ./cmd/editor-release verify \
  -root .. -input ../downloaded-release -output ../unused \
  -version v0.2.0 -commit <full-tag-commit> -epoch <commit-epoch>
```

The workflow never creates or mutates tags. Tag creation is restricted to the
maintainer and a second active ruleset forbids all release-tag updates and
deletions.
