# Zed release security

The Zed extension uses a repository-specific Ed25519 signing identity. The
private PKCS#8 key exists only as `SPICE_EDITOR_RELEASE_SIGNING_KEY` in the
protected `release-signing` GitHub environment. Its public trust anchor is
committed at `security/release/ed25519-public.pem`. The raw Ed25519 public-key
SHA-256 fingerprint is
`4c85bbb1d629601f472b5be1c8dd1596ae4ccb4e2d0add3843c1653d6c0594dd`.
The canonical SubjectPublicKeyInfo DER SHA-256 fingerprint is
`42c2d6b10a9b70285dee5c777b6bec962f2a82afb359f592ce5e6bb194cfd156`.

## Approval and authority model

`release-signing` and `release-publish` each require the repository maintainer
and accept deployments only from `v*` tags. Because the organization currently
has one maintainer, GitHub is configured with `prevent_self_review=false`; this
is an explicit availability tradeoff, not an assertion of independent human
review. The separate sequential boundaries still require two deliberate
approvals after deterministic source validation and again after independent
verification. Adding a second maintainer should be followed by enabling
self-review prevention.

An active `Release tag creation authority` ruleset restricts `v*` creation to
the maintainer. A separate `Immutable release tags` ruleset has no bypass and
forbids updates and deletion. The release workflow cannot create or change a
tag and verifies that the tag resolves to the checked-out commit on `main`.

## Artifact trust model

The uncredentialed Linux job runs the complete source gate and constructs the
unsigned archive, SPDX 2.3 SBOM, in-toto provenance, and canonical SHA-256
checksums. A Windows job independently rebuilds the WASI module and package
without signing material. The read-only signing job authenticates only the
validated checksum file and refuses any key that does not match the committed
anchor. A subsequent read-only job verifies the signature and exact Linux/
Windows bytes. Only then may the separately approved publisher receive
`contents: write`; it re-verifies the candidate, publishes exactly six files,
downloads them, compares their bytes, and verifies them again before removing
the draft flag.

All third-party actions use immutable commit IDs. Artifacts are bounded in
size, archive paths and file types fail closed, metadata contains no absolute
paths or current timestamps, and the source commit time is the sole archive
timestamp.
