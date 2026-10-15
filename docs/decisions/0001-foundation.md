# ADR 0001: small workspace and explicit trust boundaries

Status: accepted before implementation.

Context: establish real vertical slice without mobile UI or false production integration.

Decision: group protocol/identity/storage/matching into core, keep network and intelligence separate, export minimal UniFFI facade. Use Tokio/libp2p TCP+Noise+Yamux and Kademlia with directed RPC. SQLite persists leases, envelopes and client matching state. BLAKE3 addresses normalized photo bytes. Ed25519 signs purpose-separated deterministic structs; RFC 9180 HPKE encrypts directed messages. Development issuer and deterministic safety/embedding fixtures are explicitly nonproduction.

Alternatives: per-domain crates add coordination overhead; single crate exposes transport dependencies to mobile; DHT blobs confuse discovery with durability; custom encryption increases audit burden; global Elo violates product model. QUIC remains compatible future transport.

Consequences: initial routing/bootstrap is local and explicit; production privacy, signed revocation distribution, NAT relay, real model and encrypted account recovery remain release gates. Memory-only account keys avoid plaintext default but prevent durable account reopening until protected store adapter exists. Changes to signed encoding require new version and test vectors.
