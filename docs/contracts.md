# Milestone contracts — established before Rust implementation

Status at contract creation: specification only. Implementations must update [progress](progress.md) with proof and omissions. Logical names below map to Rust types or modules; an implementation mapping is recorded in [UML](uml/README.md).

## Ownership and workspace

- `annoda-core`: `protocol`, `identity`, `storage`, `matching`. Owns shared domain structs, signing bytes, HPKE envelopes, SQLite persistence, content hashes. No dependency on network or intelligence.
- `annoda-network`: libp2p request/response, Kademlia, bounded actor and replication client; depends on core. Owns node and simulator executables and real network tests.
- `annoda-intelligence`: `ranking`, `safety`; depends on core only if needed.
- `annoda-mobile-ffi`: UniFFI facade; depends on core and intelligence. Network lifecycle interface may remain planned when not safely integrated.

Core contract names are negotiable before code is written, but public behavior is fixed here. Every signature binds version, message kind, sender, recipient where applicable, timestamps and payload. Profile identity is derived from signing public key. An issuer binds both signing and encryption keys; neither is accepted from an unsigned mailbox hint. Secrets remain in memory or protected by an encrypted key store; no default plaintext private-key files.

## Types and operations

`DeviceKeyPair`: generate, public signing key, public HPKE key, sign, recipient decrypt. No serialization of secret keys by default.
`IdentityIssuer`: issue a `VerifiedCredential` from authenticated private identity attributes, never an unverified public age field. `DevelopmentIssuer` is explicitly synthetic. Credential contains version, random serial, issuer id, subject signing and encryption keys, verified first name, attested adult age, issue and expiry times, signature. Exact age validity is limited by short credential lifetime; renewal recalculates age from private birth date in a real adapter. Validation accepts explicit time, trusted issuer keys and revocation state.
`PublicProfile`: version, owner, verified credential, photo manifests, expiry, signature. Verify credential, owner binding, signature, photo limits and expiry before acceptance.
`ContentHash`/`PhotoId`: BLAKE3 normalized photo bytes. `PhotoManifest`: owner, hash, byte count, media type. `ContentLease`: owner authorized expiry. `ReplicaRecord`: provider and content id; provider announcements are hints only.
`MessageEnvelope`: version, random id, sender, recipient, creation and expiry, kind, encrypted payload and sender signature; use standardized HPKE. Sender possession demonstrated by signature. Receiving checks destination, key binding, expiry, signature, ciphertext authentication, then transactional deduplication.
`Like` and contact payloads are encrypted. Sender credential and message kind are enclosed in an outer recipient-sealed `MailboxParcel`; a volunteer receives only recipient/id/time and opaque HPKE ciphertext. The recipient opens parcel, verifies inner sender credential/signature, and applies domain state. Volunteer learns recipient routing, sizes, timing and transport identity, never explicit sender account or like kind. See [ADR 0003](decisions/0003-sealed-mailbox.md). `LikeInbox` persists authenticated positive intents; recipient can inspect sender before acceptance.
`MatchState`: Neutral, Outgoing, Incoming, Matched, Rejected, Blocked. Incoming+local like and Outgoing+remote like become Matched. Reject clears eligibility; blocking is terminal until explicit unblock policy (planned). Duplicate delivery is a no-op. Contact disclosure before Matched or after Blocked fails. Private contact handles never enter public records.
`PeerStorage`: persist signed profiles, hash-verified photo blobs, opaque mailbox messages, leases and tombstones with capacity bounds. Reads and restarts enforce expiry. Fetching mailbox data requires recipient proof of possession; public photos are readable. Acknowledgement must not permit third-party deletion. Durable delivery is retention by available volunteers, not guaranteed delivery.
`PeerNode`: start with trusted issuer configuration and limits; connect using explicit local bootstrap addresses; publish/fetch profile and blobs; store/poll mailbox; replicate to configured peer count; shutdown cleanly. No unbounded channels. Networking functions return errors/timeouts, never fabricated success. Node-owned clock is injected for tests; RPC timestamps never control validation time. Bound pending provider queries as well as directed requests. Discovery must return candidate profiles without requiring the caller to know candidate account ids in advance.
`PreferenceModel`: sigmoid score, SGD feedback, reset; reject dimension mismatches and nonfinite input. Stable tie-breaking and seeded exploration. `PhotoEncoder` and `PhotoSafetyClassifier` are real extension traits; deterministic fixtures explicitly advertise lack of real inference.

## Acceptance and sequencing

Architecture, security model, contracts, five class diagrams, twelve sequence diagrams and ADRs must exist before Rust implementation begins. Write failing tests before behavior. Implement core, real local network/storage, private matching, intelligence, then facade and full validation. Agents may implement independent contracts concurrently once specification exists. Shared core API changes require coordination.

At least one automatic test must use real libp2p encrypted transports, stop Alice, retain replicated photos and Bob's encrypted like, reconnect Alice, verify both intents, and disclose contacts in encrypted payloads. Test restart persistence, invalid credentials/signatures, duplicates, missing providers, expiry and denied disclosure. Exact commands belong to root README and [testing](testing.md).
