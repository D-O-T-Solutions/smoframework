# RFC 0007 — Enrollment Protocol

## Status
ACCEPTED — incorporated into SPEC.md §VII.

**Implementation Status: ~60% Complete**

| Feature | Spec | Implemented | Notes |
|---------|------|-------------|-------|
| .smor / .smoc formats | ✅ | ✅ | Fully implemented |
| Transport abstraction (stdin/clipboard/file) | ✅ | ✅ | `smo node import` auto-detects |
| Pipe/stdout automation | ✅ | ✅ | `smo-admin sign \| smo node import` |
| Clipboard (interactive) | ✅ | ✅ | `ClipboardProvider` with 5 backends |
| Join Token v1 (CBOR+HMAC) | ✅ | ✅ | Format frozen, `generate-invite` works |
| `smo mesh join --token` | ✅ | ❌ STUB | Only prints "not yet implemented" |
| `smo node --join <token>` | ✅ | ❌ MISSING | Flag doesn't exist |
| Auto-enrollment flow | ✅ | ❌ MISSING | Manual: init→export→copy→sign→import |
| QR code | 🔮 Future | ❌ | Not started |
| Recovery Package | ✅ | ❌ MISSING | Spec only |
| Post-import summary | ✅ | ✅ | Implemented |
| Private keys never in transport | ✅ | ✅ | Invariant I-23 enforced |

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
11. **Multiple export formats:** TEXT (ASCII Armor), JSON, QR, BINARY (CBOR). Parsers auto-detect format on import.
12. **Enrollment Request (.smor)** contains: mesh_id, display_name, public_key, fingerprint, requested_role, platform, version, nonce, timestamp, signature.
13. **Membership Certificate (.smoc)** contains: mesh_id, node_public_key, display_name, role, capabilities, epoch, issued_by, issued_at, expires_at, signature.
14. **Authority validates** the request against policy before signing. No automatic approval.
15. **Atomic enrollment.** The Authority's `sign_csr()` calls `enroll_node()`, which wraps three INSERTs (node, certificate, alias) in a single SQLite transaction. Partial enrollment is impossible.
16. **display_name normalization.** All display names are lowercased and trimmed before storage and comparison. "SOC-HN-01" and "soc-hn-01" collide as the same name.
17. **UNIQUE constraint for race safety.** The `nodes` table has `UNIQUE(display_name)`. The `node_aliases` table has `UNIQUE(alias)`. The registry does NOT use SELECT-before-INSERT. It always INSERTs first and catches `SQLITE_CONSTRAINT_UNIQUE`. This is immune to TOCTOU races.
18. **Error code 220 — DisplayNameAlreadyExists.** Mapped from `SQLITE_CONSTRAINT_UNIQUE`. `Severity: Warn`, `RetryClass: RetrySafe`, `Recovery: None`. The node proposes a different name and retries.
19. **display_name validation** before insertion: non-empty, ≤128 chars, starts with alphanumeric, only `[a-zA-Z0-9._-]`. Errors 221 (InvalidDisplayName) and 222 (DisplayNameTooLong) are returned for violations.
20. **CipherSuite is a property of the Mesh**, not the Node. `MeshConfig` carries `cipher_suite_id`; all nodes in a mesh use the same suite. No cipher negotiation at enrollment time. Suite is locked per mesh epoch. When `mesh_epoch` changes, `cipher_suite_id` MAY stay the same or change.
21. **`MeshConfig.hmac_secret`** is a 32-byte random hex key auto-generated at mesh creation and written into `mesh.json`. It is used to HMAC-sign all Join Tokens for that mesh. The Authority reads it from `mesh.json` during `generate_invite()` and during `sign_csr()` (to validate the token).
22. **Bootstrap endpoints are a property of the Mesh, not the Join Token generator.** `MeshConfig` stores `bootstrap_endpoints[]` and `advertise_addresses[]`. These are configured once via `smo-admin mesh publish` (interactive wizard) and read by `generate-invite` automatically. The operator does NOT pass `--endpoint` to `generate-invite` after publish.
23. **Listen Address vs Advertise Address are separate concepts.** `listen_address` (default `0.0.0.0:7777`) is what the daemon binds to. `advertise_addresses[]` are what peers connect to (DNS name, public IP, private IP). This follows Kubernetes/Consul/RabbitMQ convention.
23. **Mesh is not considered "online" until publish.** `create-mesh` generates keys + mesh.json offline. `mesh publish` configures network endpoints, verifies port availability, detects NAT, and marks bootstrap as ready. `smo-node --daemon` refuses to start without published endpoints. `generate-invite` returns error 223 (BOOTSTRAP_NOT_CONFIGURED) if called before publish.
24. **Port availability is verified at publish time** via `bind()` probe with `SO_REUSEADDR`. It does NOT open a permanent socket — the daemon does that on startup. The check is advisory (race conditions exist, but the operator is informed).
24. **Cloud firewall is an informational reminder, not automated.** SMO prints platform-specific instructions (AWS, Azure, GCP, OCI, UFW, iptables) during publish. It does NOT attempt to open ports — cloud APIs are too diverse.
25. **NAT detection is informational.** If private IP ≠ public IP, SMO warns the operator and suggests port forwarding or DNS. It does NOT attempt UPnP/IGD/NAT-PMP automatically.
25. **Publish is idempotent.** Running `mesh publish` again updates `bootstrap_endpoints` and `advertise_addresses`. All Join Tokens generated afterward use the new endpoints. Old tokens (with old endpoints) remain valid until expiry — the new node connects to any endpoint in the token.

## Implementation Gaps (Must Fix for Sprint 5D)

| Gap | Location | Effort |
|-----|----------|--------|
| `mesh join --token` stub | `cmd/smo-cli/main.cpp:508` | ~2h |
| `smo node --join <token>` flag | `cmd/smo-node/main.cpp` | ~1h |
| Auto-enrollment flow | New: `cmd/smo-node/join.cpp` | ~4h |
| Auto-bootstrap from token | `cmd/smo-node/join.cpp` | ~2h |
| Port check hardcoded 7777 | `core/network/port_check.cpp` | ~30m |
| Recovery Package | `cmd/smo-admin/recovery.cpp` | ~3h |

## Rationale
... (keep existing rationale)

## Consequences
... (keep existing consequences)

## Implementation Plan (Sprint 5D)

### Phase 1: Zero-Touch Join (P0)
1. Add `--join <token>` flag to `smo-node` (`cmd/smo-node/main.cpp`)
2. Implement `cmd/smo-node/join.cpp`:
   - Parse token (CBOR + HMAC)
   - Extract `bootstrap_endpoints[]`, `mesh_id`, `cipher_suite_id`, `role`, `expiry`
   - Connect to first available bootstrap endpoint
   - Send CSR (auto-generate if no identity)
   - Receive certificate
   - Import certificate
   - Start daemon with `--seed` from token
2. Implement `mesh join --token` in `cmd/smo-cli/main.cpp`:
   - Parse token, delegate to `smo-node --join` via subprocess
   - Print progress: "Connecting to authority... CSR sent... Certificate received... Daemon started"

### Phase 2: Operations Tooling (P0)
1. `smo doctor` - system health check
2. `smo mesh validate` - mesh.json validation
3. `smo topology` - mesh topology view
4. `smo registry` - node registry browser

### Phase 3: Operations Polish (P1)
1. `smo mesh recover` - recovery package import
2. `smo mesh authority add/revoke` - multi-authority
4. `smo mesh epoch increment` - epoch management
5. `smo history` - contract execution history

---

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
