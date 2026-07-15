# RFC 0007 — Enrollment Protocol

## Status
ACCEPTED — incorporated into SPEC.md §IX.

## Problem
How does a new node deliver its Public Key to an Authority and receive a verifiable Membership Certificate?

## Decisions
1. **Enrollment is transport-agnostic.** The protocol defines the `.smor` (enrollment request) and `.smoc` (membership certificate) formats. The carrier (file, clipboard, QR, API, Bluetooth) is implementation-specific.
2. **Two-file workflow** mirrors SSH: `smo-node init` → `smo export` (generates `.smor`) → `smo-admin sign` (produces `.smoc`) → `smo-node import` (installs certificate).
3. **Join Token** for automated enrollment: QR-encoded single-use, time-limited token (SMO://JOIN?mesh=&token=&bootstrap=). Node scans, connects, sends CSR, receives cert.
4. **Multiple export formats:** TEXT (ASCII Armor), JSON, QR, BINARY (CBOR). Parsers auto-detect format on import.
5. **Enrollment Request (.smor)** contains: mesh_id, node_name, public_key, fingerprint, requested_role, requested_capabilities, nonce, timestamp, signature.
6. **Membership Certificate (.smoc)** contains: mesh_id, node_public_key, role, capabilities, epoch, issued_by, issued_at, expires_at, signature.
7. **Authority validates** the request against policy before signing. No automatic approval.

## Rationale
- File-based enrollment is simple, auditable, and works in air-gapped environments where no network enrollment is possible.
- Multiple export formats let deployments choose the right carrier without changing the protocol.
- Join Token enables automated onboarding without requiring file transfer, while remaining single-use and time-limited.
- Mirrors SSH's proven UX pattern reduces learning curve for operators.

## Consequences
- Every deployment must implement at least one carrier (file recommended; API for cloud).
- Join Token requires a bootstrap endpoint on the mesh for automated enrollment.
- QR mode requires terminal QR libraries or a web UI for mobile scanning.
- Authority policy for auto-approval vs. manual approval is deployment-specific and not prescribed by the protocol.
