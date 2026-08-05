# Spice for Zed

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

## Compatibility and verification

Version `0.2.0` is pre-release software and is tested against Spice
`v0.0.0-20260805081925-09f55f01bb38`, Go 1.26.5, Rust 1.93.0, and
`zed_extension_api` 0.7.0. The compatibility version is intentionally exact
until coordinated preview tags exist.

Run the repository gate from the root:

```text
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked --release --target wasm32-wasip2
cd fixture
go mod download
GOPROXY=off go tool github.com/spice-framework/spice/cmd/spice verify --format=json ./...
```

The fixture uses the public canonical module with no `replace` directive.
