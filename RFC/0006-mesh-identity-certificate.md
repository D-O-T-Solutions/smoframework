# RFC 0006 — Mesh Identity & Certificate Model

## Status
ACCEPTED — AMENDED 2026-08-14 (§AMEND-1 identity primitive suite-selected; §AMEND-2 revocation = Capability Epoch + Revocation Set; §AMEND-3 recovery domain). Incorporated into SPEC.md §VII.

## Problem
How do nodes establish verifiable identity within a mesh, and how are cryptographic authorities structured so that membership can be verified by any node without a central service?

## Decisions

> **AMEND-1 (2026-08-14, supersedes original Decision 1):** Identity primitive is **suite-selected**, resolved via `CryptoRegistry` from `MeshConfig.cipher_suite_id` — NOT hardcoded Ed25519.
> - Suite 1/2 → Ed25519; Suite 3 → **ML-DSA-65** (per RFC 0024 canonical suite table).
> - Root identity / Authority identity / Certificate signing all follow the mesh suite. Under the current genesis decision (Root = Suite 3 / ML-DSA-65), identity signing = ML-DSA-65.
> - NodeID derivation: `Hash(NodePublicKey)` where Hash = suite hash (SHA-256 for Suite 1, BLAKE3-256 for Suite 2/3). NodeID is a hash of the public key; the algorithm derives from the suite, never from byte length.

1. **Identity primitive is suite-selected (AMEND-1).** NodeID = SuiteHash(NodePublicKey). The public key is the node's identity; the private key never leaves the node.
2. **Three-tier key hierarchy:** Root (offline) → Authority (online, signs certs) → Node (daily operations).
3. **Membership Certificate (.smoc)** binds a node's PublicKey to a MeshID, role, capability set, and epoch. Verifiable by any node holding the Root Public Key.

> **AMEND-2 (2026-08-14, supersedes original Decision 4):** Revocation uses **Capability Epoch + Revocation Set** — two complementary mechanisms, NOT "epoch replaces CRL" alone.
> - **Capability Epoch = coarse-grained global capability invalidation.** Incrementing the epoch invalidates ALL credentials authorized under older epochs.
> - **Revocation Set (fine-grained) = identity/certificate/key_id specific invalidation.** Revokes a specific cert serial / key_id / authority without a global epoch bump.
> - Epoch is the primary incident-response primitive; the Revocation Set is the compatibility/detail layer.
> - **No auto-revoke on offline/heartbeat timeout.** Offline ≠ compromised. Revocation requires an explicit governance decision.
> - Every authorization-sensitive check compares `credential.capability_epoch >= mesh.current_epoch`; a revoked identity is additionally rejected by the Revocation Set.

4. **Capability Epoch + Revocation Set (AMEND-2).** Epoch is the coarse-grained global capability invalidation primitive; the Revocation Set is the fine-grained per-identity/per-key invalidation layer. Epoch is not the only mechanism; a CRL-style set remains for precise revocation.

> **AMEND-3 (2026-08-14):** Recovery is a **dedicated cryptographic domain** and does NOT inherit the mesh Crypto Suite AEAD.
> - **Recovery KDF: Argon2id** (memory-hard, makes offline passphrase guessing expensive — NOT for "better encryption").
> - **Recovery AEAD: AES-256-GCM** (confidentiality + integrity of the recovery blob) with **nonce 12 bytes** (AES-GCM nonce size — NOT 24B from XChaCha20).
> - **salt: 32 bytes; tag: 16 bytes** (from AEAD).
> - This is consistent with the crypto-domain ≠ cipher-suite principle; recovery intentionally differs from the mesh suite AEAD.
> - **Recovery ≠ resurrection.** Decrypting `authority.sec` / recovery shares alone does NOT restore live authority. Reconstruction MUST be **governance-authorized**: Shamir M-of-N → offline reconstruction → governance rekey/election → new authority → new epoch.

5. **Root Key never circulates.** Generated at mesh creation, used once to sign the first Authority certificate, exported as encrypted Recovery Package (Recovery domain: Argon2id + AES-256-GCM, AMEND-3), then deleted from runtime.
6. **Recovery Authorities** use Shamir Secret Sharing (M-of-N threshold) to reconstruct the Root Key if lost. Reconstruction is offline + governance-authorized (AMEND-3).
7. **Session binding** requires two independent proofs: a valid Membership Certificate (chain up to Root, epoch >= current) and a signed nonce (proves key possession).
8. **Single node, multiple meshes.** The node's Identity keypair is shared; each mesh membership is a separate certificate with its own epoch and capabilities.

## Rationale
- Private keys never traveling eliminates the most common attack vector in PKI.
- Epoch + Revocation Set is more robust than CRL or OCSP alone in a mesh where nodes may be offline: epoch invalidates broad capability in one governance commit; the Revocation Set handles precise per-identity revocation.
- Three-tier hierarchy isolates Root exposure: compromise of an Authority key does not compromise the mesh.
- Two-factor session binding (certificate + signed nonce) prevents replay and key theft.
- Argon2id makes offline passphrase guessing expensive; AES-256-GCM provides confidentiality + integrity for the recovery blob; governance-authorized reconstruction prevents a share-holder from silently resurrecting authority.

## Consequences
- Mesh creation is a heavyweight operation (Root generation, Authority cert, Recovery Package export, Root deletion).
- Epoch increment is a mesh-wide event that forces all nodes to re-enroll.
- M-of-N recovery requires secure out-of-band coordination of share holders.
- Nodes must store multiple certificates if they belong to multiple meshes.
- Identity signing algorithm is determined by the mesh suite (AMEND-1). Implementers MUST NOT assume Ed25519.
- Revocation is a governance action, not an automatic reaction to offline status (AMEND-2).
