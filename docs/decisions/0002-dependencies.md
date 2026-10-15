# ADR 0002: dependency selection evidence

Status: accepted; registry resolution and compiled artifacts confirmed (final workspace verification in progress.md).

2026-10-16 environment: rustc/cargo 1.99.0, current edition 2024. Primary maintained API references checked before implementation: [libp2p 0.56 request/response](https://docs.rs/libp2p/latest/libp2p/request_response/), [HPKE API](https://docs.rs/hpke/latest/hpke/), [UniFFI](https://docs.rs/uniffi/latest/uniffi/), [Tokio](https://docs.rs/tokio/latest/tokio/), [Ed25519 Dalek](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/). Search snapshots showed libp2p 0.56, hpke 0.14.1, UniFFI 0.32.1; directly opening latest libp2p revealed 0.57.0 (2026-09-11), superseding that stale search snapshot; agents must confirm registry availability/MSRV and choose compatible maintained releases, recording lockfile results rather than blindly trusting latest labels.

Decision: minimize libp2p features; use audited/established primitive implementations, HPKE rather than invented encryption; serde deterministic fixed structs; SQLite via rusqlite for local transactions; image JPEG/PNG only; UniFFI for native bindings. Pin exact resolved dependency graph in Cargo.lock. Resolve RNG version boundaries explicitly instead of unsafe conversions. Optional model runtimes are deferred until reproducible asset/license exists.

Consequences: lockfile compatibility is proven by build/tests; maintenance or audit status is not an assertion that Annoda has received security review. Run dependency security/license review before release. AGPLv3-or-later project license does not replace third-party licenses.

Selected encoding: Postcard 1.x for signed fixed structs, four-byte big-endian length-prefixed Postcard RPC capped at 8 MiB before allocation; HPKE base X25519-HKDF-SHA256/HKDF-SHA256/ChaCha20Poly1305 plus outer Ed25519 signature. This is a protocol encoding decision; future field/discriminant changes require version migration.

JSON numeric byte arrays were rejected during review: a valid 4 MiB photo can exceed the transport ceiling after expansion. The bounded binary codec shares the established serializer and introduces no cryptography. Its framing requires truncation, size and round-trip regression tests.

Resolved lockfile includes libp2p 0.57.1, HPKE 0.14.1, Tokio 1.53.3, UniFFI 0.32.2, rusqlite 0.38.0, Postcard 1.1.3, BLAKE3 1.8.7, image 0.25.9 and core Ed25519 Dalek 2.2.0 (transport also uses Dalek 3.0.0). Workspace declares tested Rust 1.99 rather than an unverified lower MSRV. Core seeds established ChaCha20 RNG from fallible OS getrandom for HPKE to avoid the library convenience helper panic on RNG failure; seeds are zeroized. No new cryptographic construction is introduced.
