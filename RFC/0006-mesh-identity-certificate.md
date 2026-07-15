# RFC 0006 — Mesh Identity & Certificate Model

## Status
ACCEPTED — incorporated into SPEC.md §VII.

## Problem
How do nodes establish verifiable identity within a mesh, and how are cryptographic authorities structured so that membership can be verified by any node without a central service?

## Decisions
1. **Ed25519 is the identity primitive.** NodeID = Blake3(NodePublicKey). The public key is the node's identity; the private key never leaves the node.
2. **Three-tier key hierarchy:** Root (offline) → Authority (online, signs certs) → Node (daily operations).
3. **Membership Certificate (.smoc)** binds a node's PublicKey to a MeshID, role, capability set, and epoch. Verifiable by any node holding the Root Public Key.
4. **Capability Epoch** replaces CRL. Incrementing the epoch invalidates all certificates issued before it. No blacklist needed.
5. **Root Key never circulates.** Generated at mesh creation, used once to sign the first Authority certificate, exported as encrypted Recovery Package (AES-256-GCM), then deleted from runtime.
6. **Recovery Authorities** use Shamir Secret Sharing (M-of-N threshold) to reconstruct the Root Key if lost.
7. **Session binding** requires two independent proofs: a valid Membership Certificate (chain up to Root) and a signed nonce (proves key possession).
8. **Single node, multiple meshes.** The node's Identity keypair is shared; each mesh membership is a separate certificate with its own epoch and capabilities.

## Rationale
- Private keys never traveling eliminates the most common attack vector in PKI.
- Epoch-based revocation is simpler and more robust than CRL or OCSP in a mesh where nodes may be offline.
- Three-tier hierarchy isolates Root exposure: compromise of an Authority key does not compromise the mesh.
- Two-factor session binding (certificate + signed nonce) prevents replay and key theft.

## Consequences
- Mesh creation is a heavyweight operation (Root generation, Authority cert, Recovery Package export, Root deletion).
- Epoch increment is a mesh-wide event that forces all nodes to re-enroll.
- M-of-N recovery requires secure out-of-band coordination of share holders.
- Nodes must store multiple certificates if they belong to multiple meshes.
