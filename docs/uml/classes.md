# Domain class models

All diagrams are normative logical models. Names map to structs/enums/traits in modules listed below; actual delivered paths are tracked in [progress](../progress.md). Multiplicities describe domain ownership, not Rust allocation layout.

## A. Identity and account

```mermaid
classDiagram
    class UserIdentity {
        +ProfileId id
        +VerifiedCredential credential
        +verify(now) Result
    }
    class ProfileId {
        +bytes32 digest
        +from_key(public_key) ProfileId
    }
    class DeviceKeyPair {
        -SigningKey signing
        -HpkePrivateKey encryption
        +generate() DeviceKeyPair
        +sign(bytes) Signature
        +decrypt(envelope) Payload
    }
    class VerifiedCredential {
        +u16 version
        +String issuer_id
        +bytes32 subject_key
        +bytes32 encryption_key
        +String first_name
        +u8 age
        +u64 expires_at
        +bytes signature
        +verify(trust, now) Result
    }
    class TrustedIssuer {
        +String id
        +bytes32 public_key
        +Set revoked_serials
    }
    class PublicProfile {
        +ProfileId owner
        +u64 expires_at
        +bytes signature
        +validate(trust, now) Result
    }
    class VerificationService {
        <<interface>>
        +authenticate_cie(response) PrivateAttributes
        +prove_possession(challenge) Result
    }
    class IdentityIssuer {
        <<interface>>
        +issue(attributes, public_keys) VerifiedCredential
    }
    UserIdentity "1" *-- "1" ProfileId
    UserIdentity "1" *-- "1" DeviceKeyPair
    UserIdentity "1" o-- "1..*" VerifiedCredential
    PublicProfile "1" *-- "1" VerifiedCredential
    VerifiedCredential "0..*" --> "1" TrustedIssuer : verified by
    VerificationService ..> IdentityIssuer : authenticates before issuing
    IdentityIssuer ..> VerifiedCredential : creates
    PublicProfile "0..*" --> "1" ProfileId : owned by
```

Mapping: core::identity structs DeviceKeyPair, VerifiedCredential, TrustedIssuer; core::protocol ProfileId/PublicProfile; IdentityIssuer trait. UserIdentity is account aggregate; VerificationService is planned CIE adapter trait/module. Invariants: credential subject matches owner and signing proof; issuer binds both keys; public age/name derived from attestation; private identity attributes never enter DHT. [Identity authority](../identity.md).

## B. Photographs and distributed storage

```mermaid
classDiagram
    class PhotoId {
        +ContentHash hash
    }
    class ContentHash {
        +bytes32 digest
        +verify(blob) bool
    }
    class PhotoManifest {
        +PhotoId id
        +ProfileId owner
        +u64 byte_count
        +String media_type
    }
    class PhotoBlob {
        +bytes normalized_bytes
    }
    class StorageNode {
        +u64 capacity_bytes
        +put(manifest, blob, lease) Result
        +get(id, now) PhotoBlob
        +expire(now) Result
    }
    class ReplicaRecord {
        +String provider
        +PhotoId id
        +u64 expires_at
    }
    class ReplicationPolicy {
        +u16 target_count
        +u64 maximum_lease
        +repair(providers) Result
    }
    class ContentLease {
        +ProfileId owner
        +u64 expires_at
        +bytes authorization
    }
    PhotoId "1" *-- "1" ContentHash
    PhotoManifest "1" --> "1" PhotoId
    PhotoBlob "1" --> "1" ContentHash : verified against
    StorageNode "1" o-- "0..*" PhotoBlob
    StorageNode "1" *-- "0..*" ContentLease
    ContentLease "1..*" --> "1" PhotoId
    ReplicaRecord "0..*" --> "1" PhotoId
    ReplicationPolicy ..> ReplicaRecord
    StorageNode "1" --> "1" ReplicationPolicy
```

Mapping: core::storage content/hash, manifest/blob/lease structs and SQLite PeerStorage; network::replication implements StorageNode/ReplicationPolicy behavior; provider metadata maps ReplicaRecord. Logical wrapper names may be type aliases. Invariants: hash verifies bytes; independent owners have distinct leases; expiry prevents reads immediately; replication success requires distinct acknowledgements. [Storage authority](../storage.md).

## C. Matching

```mermaid
classDiagram
    class Like {
        +String id
        +ProfileId sender
        +ProfileId recipient
        +u64 expires_at
    }
    class Pass {
        +ProfileId candidate
        +u64 created_at
    }
    class LikeInbox {
        +receive(envelope) Result
        +list() List
        +accept(sender) MatchState
        +reject(sender) Result
    }
    class Match {
        +ProfileId first
        +ProfileId second
        +MatchState state
        +apply(event) Result
    }
    class MatchState {
        <<enumeration>>
        Neutral
        Outgoing
        Incoming
        Matched
        Rejected
        Blocked
    }
    class ContactHandle {
        +String service
        +String value
    }
    class ContactDisclosure {
        +String match_id
        +ProfileId sender
        +ProfileId recipient
        +encrypt_for_recipient() Envelope
    }
    LikeInbox "1" *-- "0..*" Like
    Match "1" --> "2" Like : valid positive evidence
    Match "1" *-- "1" MatchState
    Pass ..> Match : prevents matching
    ContactDisclosure "0..*" --> "1" Match : requires matched state
    ContactDisclosure "1" *-- "1..*" ContactHandle
```

Mapping: core::matching structs/enums and SQLite inbox/state service. LikeInbox and Match may be service/record combinations; MatchState is enum; Pass can map private state transition. Invariants: sender authenticated, recipient alone decrypts, duplicates do not reapply, rejection/blocking cannot be bypassed by delay, contacts gated separately. [State table](../matching.md).

## D. Network

```mermaid
classDiagram
    class PeerNode {
        +start(config) Result
        +publish(profile) Result
        +replicate(blob, peers) Result
        +poll_mailbox(proof) List
        +shutdown() Result
    }
    class NodeIdentity {
        -bytes transport_secret
        +String peer_id
    }
    class PeerDiscovery {
        +find_providers(id) List
        +find_profiles(query) List
    }
    class MessageEnvelope {
        +u16 version
        +String id
        +ProfileId sender
        +ProfileId recipient
        +u64 expires_at
        +bytes ciphertext
        +bytes signature
    }
    class MailboxParcel {
        +u16 version
        +String id
        +ProfileId recipient
        +u64 expires_at
        +bytes sealed_message
        +open(recipient_key) MessageEnvelope
    }
    class PeerStorage {
        +put(record) Result
        +fetch(key, now) Result
        +expire(now) Result
    }
    class Transport {
        <<interface>>
        +listen(address) Result
        +request(peer, message) Response
    }
    class RelayNode {
        +reserve(peer) Result
        +forward(stream) Result
    }
    PeerNode "1" *-- "1" NodeIdentity
    PeerNode "1" *-- "1" PeerDiscovery
    PeerNode "1" *-- "1" PeerStorage
    PeerNode "1" --> "1" Transport
    PeerStorage "1" o-- "0..*" MailboxParcel
    MailboxParcel "1" *-- "1" MessageEnvelope : encrypted contents
    RelayNode ..|> Transport
    PeerDiscovery ..> PeerNode : discovers independent nodes
```

Mapping: network PeerNode actor, libp2p identity NodeIdentity, Kademlia PeerDiscovery, request/response Transport; core protocol MessageEnvelope, SQLite PeerStorage. RelayNode is planned libp2p circuit-relay adapter, not storage forwarding. Invariants: account identity independent of transport; bounded queues/frames; RPC authentication independent of Noise connection. [Network](../network.md).

## E. Ranking

```mermaid
classDiagram
    class PreferenceModel {
        -List weights
        -f64 bias
        +score(embedding) RankingScore
        +update(feedback) Result
        +reset() Result
    }
    class PhotoEmbedding {
        +u16 version
        +List values
    }
    class RankingCandidate {
        +ProfileId id
        +u8 verified_age
        +String coarse_region
    }
    class RankingScore {
        +f64 probability
    }
    class SwipeFeedback {
        +ProfileId candidate
        +bool liked
    }
    class CandidateFilter {
        +u8 minimum_age
        +u8 maximum_age
        +String coarse_region
        +allows(candidate) bool
    }
    class PhotoEncoder {
        <<interface>>
        +encode(photo) PhotoEmbedding
    }
    PreferenceModel "1" ..> "0..*" SwipeFeedback : learns locally
    PreferenceModel ..> RankingScore : produces
    RankingCandidate "1" *-- "1..*" PhotoEmbedding
    CandidateFilter ..> RankingCandidate : filters before scoring
    PhotoEncoder ..> PhotoEmbedding : creates
    PreferenceModel ..> PhotoEmbedding : fixed dimension
```

Mapping: intelligence::ranking structs PreferenceModel, PhotoEmbedding, RankingCandidate, RankingScore, SwipeFeedback, CandidateFilter and PhotoEncoder trait. Fields may be equivalent wrappers; no scores enter protocol. Invariants: finite vectors, fixed encoder version/dimension, local training, explicit sensitive filters, deterministic test seed. [Mathematics](../ranking.md).
