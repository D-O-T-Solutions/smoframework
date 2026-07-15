# protocol/

Wire format definitions. Every byte on the wire conforms to these structures.

Modules:
- `packet/`     — Packet structure and zero-copy parsing (§VI.1)
- `schema/`     — Message type enumeration and versioning
- `signing/`    — Ed25519 signing and verification (§XV.1)
- `encryption/` — XChaCha20-Poly1305 symmetric encryption (§XV.1)
- `replay/`     — Replay protection (nonce + timestamp window) (§VI.2)
