# Protocol v1

Normative entities: [contracts](contracts.md). Protocol id is versioned, e.g. `/annoda/1`; incompatible changes require another id and migration ADR. Unknown versions and message kinds fail closed. Signed encoding uses Postcard 1.x serde serialization of fixed ordered structs, no maps, floats, platform-sized integers or ambiguous optional representations. RPC transport uses a four-byte unsigned big-endian payload length followed by Postcard bytes, with an 8 MiB maximum checked before payload allocation. Signatures cover reconstructed fixed Postcard claims. Reject truncated and oversized frames; request timeout bounds incomplete senders. Struct field order and enum discriminants are protocol contracts. Implementations must document exact serializer and domain prefixes in [progress](progress.md) before interoperability claims. Receiver verifies reconstructed canonical bytes, never an arbitrary reserialized map. Golden vectors are required before public interoperability.

Public record: signed profile with credential, ordered photo manifests and expiry. DHT contains only bounded public profile/provider metadata, no photo bytes, contact handles, private likes, birthdates, fiscal codes, surnames or state subject identifiers. Directed RPC carries profile and blob put/get, mailbox deposit/fetch, and tombstones. Kademlia discovery is advisory, never proof of authenticity or durable storage. Gossipsub is unnecessary for first local milestone.

Every envelope signature has an Annoda-specific domain separator and includes version, kind, id, sender, recipient, issued-at, expires-at and encrypted bytes. Recipient HPKE uses RFC 9180 base mode with X25519-HKDF-SHA256, HKDF-SHA256 and ChaCha20Poly1305; sender authentication comes from the outer Ed25519 signature; context binds Annoda version and purpose. Do not reuse signing keys as encryption keys. Credential binds both. Signed timestamps are checked using explicit clock input: issue ≤ now < expiry; reject invalid intervals and excessive lifetimes. No acceptance based solely on transport PeerId.

Concrete baseline limits: 4 MiB normalized image, 4096 pixels per dimension, 16 million pixels, 6 photos/profile, 16 KiB profile, 64 KiB private envelope, 8 MiB frame ceiling, bounded 32-command actor queue, request timeout, configured connection and storage caps. Implementations may choose tighter limits and must record actual limits. Reject over-limit lengths before allocating/decoding when possible. Header validation precedes expensive crypto/image work. Retention scans are bounded; malformed requests receive typed errors without secrets.

Replay protection: random 128-bit or stronger id signed with message context; SQLite uniqueness over authenticated message id and recipient; commit message and seen marker atomically. Keep seen ids through message expiry. Repeated valid deposits are idempotent and do not extend expiry. Poll and ack requests bind recipient, challenge/time and operation. Restarting nodes must not reset replay state. Public profile updates require monotonic revision or explicit stale-update protection; rollback protection is mandatory before Internet deployment if deferred in milestone.

## Trusted time boundary

Every volunteer samples its own clock for validation, reads, expiry and cleanup. Domain APIs accept explicit time for testability; a network caller never chooses that time. Deterministic simulations inject a fixed/controlled node clock. A timestamp carried in a signed poll proof is only evidence subject to bounded skew against node time, never the authority used for SQL expiry. Requests with forged past/future time cannot resurrect expired records or purge current mailboxes.

## Sealed mailbox carrier

`MailboxParcel` carries only version, recipient account, random parcel id, issued/expiry and HPKE ciphertext of the complete signed `StoredMessage` (sender credential plus signed encrypted inner envelope). Recipient-only outer HPKE binds header as associated data and a distinct Annoda mailbox purpose. Carrier recipient/time must agree with inner authenticated envelope after opening; outer random parcel id is independent from signed inner message id and is bound by HPKE associated data; mismatches fail. Deposit RPC and volunteer SQLite contain only this carrier. Inner sender credential, signature, message kind and payload are not sent separately to volunteers. Recipient verifies issuer and sender after decrypting, before state mutation.

Initial implementation may retain nested HPKE to reuse the already signed inner message protocol; this is an explicit interoperability cost, not a new cryptographic primitive. Generic carriers support likes and contacts identically. Storage cannot authenticate the hidden account at deposit, so it validates carrier structure/time and imposes quotas; recipient owns full message authentication. Ciphertext retention acknowledgement never means positive-intent authentication. Do not expose hidden sender through tracing or provider keys. Transport source/timing can still correlate users; sender anonymity is not promised.

## v1 field order and discriminants

Postcard uses its documented integer/sequence encoding. Arrays have fixed element count, variable bytes/strings and vectors have lengths. All times below are Unix seconds (`u64`), all account/content ids `[u8;32]`, signatures Ed25519 byte vectors of length 64. The following order is normative; signature fields are omitted from their own claims.

| Record | Ordered fields |
|---|---|
| CredentialClaims | version:u16, serial:[u8;16], issuer_id:[u8;32], subject:ProfileId, signing_key:[u8;32], encryption_key:Vec<u8> (32 bytes), first_name:String (≤80 UTF-8 bytes), age_at_issue:u8, issued_at:u64, expires_at:u64 |
| VerifiedCredential | claims:CredentialClaims, signature:Vec<u8> |
| PhotoManifest | hash:ContentHash, byte_count:u32, media_type:String (`image/jpeg` or `image/png`) |
| ProfileClaims | version:u16, revision:u64 (>0), owner:ProfileId, credential:VerifiedCredential, photos:Vec<PhotoManifest>, expires_at:u64 |
| PublicProfile | ProfileClaims fields in same order, signature:Vec<u8> |
| EnvelopeClaims | version:u16, id:[u8;16], kind:MessageKind, sender:ProfileId, recipient:ProfileId, issued_at:u64, expires_at:u64, ciphertext:Vec<u8> |
| MessageEnvelope | EnvelopeClaims fields in same order, signature:Vec<u8> |
| LeaseClaims | owner:ProfileId, hash:ContentHash, byte_count:u32, issued_at:u64, expires_at:u64 |
| ContentLease | LeaseClaims fields in same order, signature:Vec<u8> |
| StoredMessage (sealed) | envelope:MessageEnvelope, sender_credential:VerifiedCredential |
| MailboxAad | version:u16, id:[u8;16] (independent parcel id), recipient:ProfileId, issued_at:u64, expires_at:u64 |
| MailboxParcel | MailboxAad fields in same order, ciphertext:Vec<u8> |
| PollClaims | recipient:ProfileId, challenge:[u8;32], now:u64 (proof time) |
| LikeIntent (encrypted) | sender:ProfileId, recipient:ProfileId, id:[u8;16] (must match inner signed envelope) |
| ContactDisclosure (encrypted) | match_id:[u8;32], sender:ProfileId, recipient:ProfileId, handles:Vec<ContactHandle> |
| ContactHandle | service:ContactService, value:String (nonempty, ≤256 bytes, no control characters) |

`MessageKind` declaration order: Like=0, ContactDisclosure=1. `ContactService`: Instagram=0, Telegram=1, WhatsApp=2, Other(String)=3 (service label nonempty, ≤64 bytes). Maximum eight handles per disclosure. MatchState persists locally in order Neutral, Outgoing, Incoming, Matched, Rejected, Blocked; it is not a public broadcast.

Let `P(x)` be Postcard serialization and `||` byte concatenation. All quoted contexts below include exactly the shown terminating NUL where `\0` appears. Signatures:

- Credential: Ed25519(`annoda/credential/v1\0` || P(CredentialClaims)).
- Profile: Ed25519(`annoda/profile-signature/v1\0` || `annoda/profile/v1\0` || P(ProfileClaims)).
- Envelope: Ed25519(`annoda/envelope-signature/v1\0` || `annoda/envelope/v1\0` || P(EnvelopeClaims)).
- Lease: Ed25519(`annoda/content-lease-signature/v1\0` || `annoda/content-lease/v1\0` || P(LeaseClaims)).
- Poll proof: Ed25519(`annoda/mailbox-poll/v1\0` || `annoda/mailbox-poll/v1\0` || P(PollClaims)); repeated prefix is intentional v1 encoding. Proof time may differ from node time by at most 30 seconds; nondestructive proof replay within that interval remains possible.

All HPKE contexts use info `annoda/hpke/v1/message`. Inner associated data is `annoda/1/private-message`. Parcel associated data is `annoda/mailbox-parcel/v1\0` || P(MailboxAad). Ciphertext layout is 32-byte encapsulated X25519 key followed by AEAD ciphertext/tag as produced by the HPKE library. No private-key material is serialized. Golden vectors and external cryptographic review remain prerequisites to a public interoperability release.

RPC variant indices follow declaration order: PutProfile=0, GetProfile=1, PutPhoto=2, GetPhoto=3, DepositMailbox=4, PollMailbox=5, ListProfiles=6. Poll/List limits are `u16`, bounded before conversion. Responses: Ack=0, Duplicate=1, Profile=2, Profiles=3, Photo=4, Mailbox=5, Error=6; error codes Invalid=0, Unauthorized=1, Expired=2, Capacity=3, Internal=4. Deposit carries only MailboxParcel; Poll includes recipient credential, challenge, proof, proof_time and limit. No RPC accepts caller-selected validation time.

Raw RPC responses are untrusted. Client discovery validates returned credentials/signatures/owner binding/expiry independently of volunteer storage; a transport-authenticated peer may lie. Candidate dedup uses verified owner and newest valid revision, with deterministic output ordering. Photo retrieval validates hash before returning bytes; display additionally requires the safety pipeline.
