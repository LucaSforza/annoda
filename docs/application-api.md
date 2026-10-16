# Application API — M3 contract

Status: specified before implementation. Delivery evidence belongs in [progress](progress.md). This document owns application orchestration; cryptographic bytes, matching transitions and key protection remain authoritative in [protocol](protocol.md), [matching](matching.md) and [key management](key-management.md).

## Ownership and lifecycle

`annoda_network::client::AnnodaClient` is the high-level Rust entry point. It composes core persistence/identity, intelligence and finite network sessions. Four crates remain; [ADR 0006](decisions/0006-application-service.md) defines dependency direction. Mobile adapters delegate to this service rather than reproducing domain logic. Public mobile values contain identifiers, bounded DTOs and encoded public signed credentials, never private keys or transport objects.

Explicit create and open operations use the existing encrypted vault and exclusive lease. The client owns its unlocked account; close/lock releases it after active work drains. A closed handle reports Unauthorized. Create must never replace an existing identity. Open must not create one. All state paths belong to this account's private directory; one owner is bound to each application database. Existing M2 tables are migrated additively without resetting keys, matching, checkpoints or notifications. Concurrency uses the vault lease and serialized service access; no SQLite transaction spans a network await.

A public identity summary exposes ProfileId and both public keys solely for an authorized credential adapter. It grants no signing ability. Import verifies explicit issuer/revocation state, validity, adult attributes and exact signing AND HPKE key binding before storing the credential. Relevant operations revalidate it against the current clock. Renewal imports a newer valid attestation for the same keys; no real CIE service is added. Synthetic issuance requires an explicitly trusted development issuer and is confined to development fixtures.

## Public operations

Exact Rust signatures are recorded by rustdoc; these behavioral contracts govern every adapter.

| Operation family | Required result and invariant |
|---|---|
| create/open, identity, credential, attach credential, close | Exact persistent identity; validated minimized identity summary; explicit failures |
| published profile | Read the locally persisted signed own profile after reopen; None before first publication; verify current trust/expiry |
| publish/update profile | 1–6 normalized JPEG/PNG inputs; monotonic signed revision; durable publication receipt |
| discover | Bounded verified profile page; no prior candidate IDs; age filter, stable ordering and owner/query-bound cursor |
| fetch photo | Owner/manifest-bound hash/length/format/decode/classification verified display-ready bytes |
| like/pass | Durable positive intent and encrypted delivery operation, or private terminal rejection; one logical like per peer |
| received likes/matches | Bounded pages of authenticated sender summaries and existing FSM state; Incoming visible before reciprocation |
| disclose/received contacts | Explicit selected handles; existing mutual match and recipient binding; persisted disclosures |
| block/report | Terminal local blocking and bounded signed local report; remote reporting explicitly Unsupported/LocalOnly |
| score/feedback/reset | Local model only; durable feedback/seen state; stable ties; explicit synthetic encoder opt-in |
| sync/retry/cancel | Finite bounded outgoing replay plus existing M2 incoming processing; structured partial results |
| notifications/preferences/ack | Existing durable outbox; return never implies display acknowledgement |
| operations | Bounded inspection of durable Pending/Partial/Completed/Failed work |

Identifiers and cursors must be validated; page sizes are 1–64. Cursors bind account, collection and query, have deterministic ordering, and malformed, foreign or incompatible values fail InvalidInput. Implementations may invalidate an explicit snapshot cursor when its bounded snapshot expires, but must not silently interpret it as an arbitrary offset. Discovery excludes self, expired/revoked, blocked, rejected and explicitly seen records; matches/inbox remain separately queryable. No geography is available in signed v1 profiles: geographic filters return Unsupported. Candidate model values never enter public profiles or RPC metadata.

## Profiles and safety

Publication normalizes and classifies before signing; rejects duplicate photograph manifests. Expiry is bounded by credential expiry. Profile and all owner-signed leases/blobs are committed with the operation before remote work. Each accepted revision increases; reordering/replacement does not alter matching. Superseded pending publications cannot overwrite a newer revision. Receipts distinguish local save, distinct durable per-peer acknowledgements, remaining content and failures. Retry uses persisted bytes; no imaginary acknowledgement or distributed transaction. Full distributed deletion returns Unsupported (M4).

Discovery verifies every profile before caching and takes the newest valid revision. Fetch only accepts a hash in that owner's currently valid signed manifest, bounds compressed/decode allocation and tries alternate known providers on corruption/unavailability. Remote bytes never become display-ready before incoming classification. Required classifier unavailable means SafetyUnavailable. Deterministic classifiers/encoders require explicit development opt-in and must be labeled synthetic; no real NSFW or embedding inference is claimed. Real implementations can be injected through existing traits.

## Intent, contacts and reports

The existing matching FSM remains the sole transition authority. Sending a like transactionally saves its stable encrypted parcel, local intent and related notification before network activity. Receiving an authenticated like additionally caches its verified sender credential in the same commit, so inbox display does not depend on that sender publishing a profile. Replays create no new logical likes, matches or notification events. Queries revalidate display credentials; expired identity cannot be presented as currently verified. Local pass records private feedback/seen state and Rejected; no negative message is sent. Matched/Blocked cannot be passed or re-liked through an invented transition.

Only Matched permits explicit encrypted contact disclosure. The match id and both accounts must bind incoming content. Blocking immediately excludes discovery/interactions, cancels pending local likes/disclosures to that peer and prevents further disclosure. Already disclosed data cannot be recalled from another device. Local reports use bounded reasons/evidence and a domain-separated account signature; persistence means LocalOnly, never delivery to an authority.

## Errors and compatibility

Distinguish InvalidInput, Unauthorized/Locked, UntrustedIdentity, CredentialExpired, SafetyUnavailable/Rejected, NetworkUnavailable, StorageFull, Cancelled, Pending, Unsupported and Internal. Do not return raw SQL, secret payloads or key material in public errors. Pending/Partial remote outcomes are inspectable durable results rather than silent success. Existing M1/M2 public exports remain compatible; signed v1 bytes and wire enum discriminants do not change. Local schema additions are versioned and bounded; unknown local operation versions are rejected without deleting pending work.

[Durable operations](durable-operations.md) owns retry/recovery semantics. [Mobile integration](mobile-integration.md) owns native runtime boundaries. [UML](uml/m3.md) maps service types and interactions.

## Rust usage

The service owns the vault lease and local state; authorized issuer integration supplies only a signed public credential. Photo processing requires an explicitly configured real classifier, or deliberate development fixture opt-in for tests. Imports below are illustrative of the public API; the executable real-network workflow lives in `crates/network/tests/application_client.rs`.

```rust,no_run
use annoda_network::{SyncCancellationToken, client::{AnnodaClient, DiscoveryQuery}};

// config contains explicit trusted issuers, reachable volunteers and resource ceilings.
let mut client = AnnodaClient::open(config, passphrase)?;
client.attach_credential(issuer_signed_credential)?;
let publication = client.publish_profile(photo_inputs).await?;
// Inspect publication.operation.status and replica acknowledgements before reporting success.
let page = client.discover(DiscoveryQuery::default()).await?;
if let Some(candidate) = page.items.first() {
    if let Some(photo) = candidate.profile.photos.first() {
        let validated = client.fetch_photo(candidate.profile.owner, photo.hash).await?;
    }
    let intent = client.like(candidate.profile.owner).await?;
    // intent describes local save / volunteer retention, not recipient processing.
}
let report = client.sync(SyncCancellationToken::new()).await?;
let incoming = client.received_likes(20, None).await?;
let matches = client.matches(20, None).await?;
client.close();
```

Use `publish_profile_with_cancellation`, `discover_with_cancellation` and `fetch_photo_with_cancellation` when the host can expire the execution window. Keep the cancellation token independently accessible; avoid performing key derivation or blocking FFI waits on the native UI thread.
