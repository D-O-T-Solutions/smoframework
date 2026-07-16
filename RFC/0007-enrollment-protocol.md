# RFC 0007 — Enrollment Protocol

## Status
ACCEPTED — incorporated into SPEC.md §VII.

## Problem
How does a new node deliver its Public Key to an Authority and receive a verifiable Membership Certificate?

## Decisions
1. **Enrollment is transport-agnostic.** The protocol defines the `.smor` (enrollment request) and `.smoc` (membership certificate) formats. The carrier (file, clipboard, QR, pipe, Join Token) is implementation-specific.
2. **Enrollment Transport abstraction** — stdin/stdout, file, clipboard, Join Token, QR (future), HTTP (future). The CLI is transport-agnostic: the user chooses via flags (`--copy`, `--paste`), not via separate subcommands.
3. **`smo node import` auto-detects transport** in order: stdin → clipboard → filename → error. No format flags needed.
4. **Pipe/stdout is the automation default.** `smo-admin sign request.smor | smo node import`. Also works over SSH: `ssh admin "smo-admin sign ..." | smo node import`.
5. **Clipboard is the interactive default.** `smo-admin sign request.smor --copy` → operator switches context → `smo node import`. No file paths.
6. **Join Token (v1, CBOR)** for one-command enrollment: `smo-admin generate-invite --expire 30m --endpoint 10.0.0.1:7777` generates `SMO-JOIN-<base64url(CBOR||HMAC)>`; `smo mesh join SMO-JOIN-...` automates CSR → sign → import. The token is a CBOR map (RFC 7049 subset) containing: `version`, `mesh_id`, `mesh_epoch`, `cipher_suite_id`, `bootstrap_endpoints[]`, `role`, `expiry`, `nonce`. The HMAC is computed over the CBOR payload with the mesh's `hmac_secret` (32-byte key stored in `mesh.json`). Error 212 = invalid HMAC, 213 = expired. The token contains ONLY bootstrap data — NEVER a certificate or private key.
7. **QR code** (future) for air-gap: `smo-admin sign request.smor --qr` renders terminal QR; `smo node scan` reads via camera.
8. **Recovery Package** requires encryption before transport. `smo mesh recovery --copy` prompts for passphrase, AES-256-GCM encrypts, then copies.
9. **Post-import summary** is mandatory: NodeID, certificate fingerprint, cipher suite, mesh name, role, epoch, expiry.
10. **Private keys never enter any transport.** Private keys are generated on-node, stored in secure storage, and never serialized outside that boundary. Not even temporarily. This is invariant I-23.
8. **Multiple export formats:** TEXT (ASCII Armor), JSON, QR, BINARY (CBOR). Parsers auto-detect format on import.
9. **Enrollment Request (.smor)** contains: mesh_id, display_name, public_key, fingerprint, requested_role, platform, version, nonce, timestamp, signature.
10. **Membership Certificate (.smoc)** contains: mesh_id, node_public_key, display_name, role, capabilities, epoch, issued_by, issued_at, expires_at, signature.
11. **Authority validates** the request against policy before signing. No automatic approval.
12. **Atomic enrollment.** The Authority's `sign_csr()` calls `enroll_node()`, which wraps three INSERTs (node, certificate, alias) in a single SQLite transaction. Partial enrollment is impossible.
13. **display_name normalization.** All display names are lowercased and trimmed before storage and comparison. "SOC-HN-01" and "soc-hn-01" collide as the same name.
14. **UNIQUE constraint for race safety.** The `nodes` table has `UNIQUE(display_name)`. The `node_aliases` table has `UNIQUE(alias)`. The registry does NOT use SELECT-before-INSERT. It always INSERTs first and catches `SQLITE_CONSTRAINT_UNIQUE`. This is immune to TOCTOU races.
15. **Error code 220 — DisplayNameAlreadyExists.** Mapped from `SQLITE_CONSTRAINT_UNIQUE`. `Severity: Warn`, `RetryClass: RetrySafe`, `Recovery: None`. The node proposes a different name and retries.
16. **display_name validation** before insertion: non-empty, ≤128 chars, starts with alphanumeric, only `[a-zA-Z0-9._-]`. Errors 221 (InvalidDisplayName) and 222 (DisplayNameTooLong) are returned for violations.
17. **CipherSuite is a property of the Mesh**, not the Node. `MeshConfig` carries `cipher_suite_id`; all nodes in a mesh use the same suite. No cipher negotiation at enrollment time. Suite is locked per mesh epoch. When `mesh_epoch` changes, `cipher_suite_id` MAY stay the same or change.
18. **`MeshConfig.hmac_secret`** is a 32-byte random hex key auto-generated at mesh creation and written into `mesh.json`. It is used to HMAC-sign all Join Tokens for that mesh. The Authority reads it from `mesh.json` during `generate_invite()` and during `sign_csr()` (to validate the token).

## Rationale
- File-based enrollment is simple, auditable, and works in air-gapped environments where no network enrollment is possible.
- Clipboard removes file-path friction for daily operator workflows.
- Pipe enables Unix-native composability: `smo-admin sign request.smor | smo node import`.
- Join Token enables one-command onboarding — the operator never sees a `.smor` or `.smoc`.
- QR enables enrollment in physically isolated environments.
- Private keys never entering the copy/pipe path follows OpenSSH and modern PKI design principles.
- Transaction-based enrollment eliminates partial-enrollment states where a node is half-registered.
- UNIQUE constraint (not SELECT-before-INSERT) eliminates TOCTOU race conditions in concurrent enrollment scenarios.

## Consequences
- Every deployment must implement at least one transport (stdin/stdout recommended for automation, clipboard for interactive).
- Join Token requires a bootstrap endpoint on the mesh for automated enrollment and an HMAC secret on the Authority.
- Clipboard support uses `ClipboardProvider` abstraction with ZERO external tool dependencies: X11 via `dlopen("libX11.so.6")` (no build-time libX11-dev), OSC52 escape for SSH/headless, Win32 API native, Cocoa via built-in pbcopy/pbpaste, stdout fallback for CI/CD.
- QR mode requires terminal QR libraries (libqrencode) or a web UI for mobile scanning.
- `smo node import` must probe stdin, clipboard, and argv in order — must not block on stdin if empty.
- Post-import summary requires the CLI to retain and display enrollment metadata.
- Authority policy for auto-approval vs. manual approval is deployment-specific and not prescribed by the protocol.
- display_name normalization means "My-Node" and "my-node" cannot coexist in the same mesh.
- The NodeRegistry schema requires three tables (nodes, certificates, node_aliases) with UNIQUE constraints; the alias insert mirrors the display_name so alias-based lookups always find enrolled nodes.
- `--copy` on a private key MUST return an error or be a compile-time error. The CLI must enforce this at the argument parser level.
- Recovery Package `--copy` MUST prompt for encryption passphrase before writing to clipboard.
