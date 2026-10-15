# Interaction sequences

Each status describes milestone target versus planned adapter. Actual shipped coverage and proof: [progress](../progress.md).

## 1. Registration and CIE credential issuance

Milestone: synthetic development issuance and peer verification. Planned: real CIE adapter and interactive possession challenge.

```mermaid
sequenceDiagram
    participant Device
    participant Service as VerificationService
    participant CIE
    participant Issuer as IdentityIssuer
    participant Peer
    Device->>Device: Generate signing and HPKE keys
    Device->>Service: Public keys and possession signature
    alt production adapter (planned)
        Service->>CIE: Authenticate user
        CIE-->>Service: Authoritative private attributes
    else explicit development fixture
        Service->>Service: Load synthetic adult attributes
    end
    Service->>Service: Check adulthood and key possession
    alt adult and authorized
        Service->>Issuer: Issue minimized key-bound attestation
        Issuer-->>Device: Signed versioned expiring credential
        Device->>Peer: Signed public profile and credential
        Peer->>Peer: Verify trust, signature, keys, validity, revocation
    else underage or failed possession
        Service-->>Device: Reject, publish nothing
    end
```

## 2. Profile creation and publication

Milestone target: signed profile and actual directed volunteer transfer. Planned: global discovery policy and durable DHT publication renewal.

```mermaid
sequenceDiagram
    participant Client
    participant Safety
    participant Identity
    participant Volunteer
    participant DHT
    Client->>Safety: Normalize and validate selected photos
    Safety-->>Client: Approved bytes and hashes
    Client->>Identity: Validate current credential
    alt valid adult and approved photos
        Client->>Client: Sign ordered profile manifest and expiry
        Client->>Volunteer: Publish signed profile and leased blobs
        Volunteer->>Volunteer: Verify credential, owner, signature, quotas
        Volunteer-->>Client: Durable acknowledgement
        Volunteer->>DHT: Advertise bounded provider metadata
    else invalid credential or photo
        Client-->>Client: Reject publication with typed error
    end
```

## 3. Local photo validation before upload

Milestone: decode, limits, metadata normalization and deterministic test classifier. Planned: actual mobile model inference.

```mermaid
sequenceDiagram
    participant Picker
    participant Client
    participant Decoder
    participant Classifier as PhotoSafetyClassifier
    participant Storage
    Picker->>Client: Selected image bytes
    Client->>Client: Check encoded byte limit
    Client->>Decoder: Decode with allocation and pixel limits
    alt malformed or oversized
        Decoder-->>Client: Reject
    else valid structure
        Decoder-->>Client: Pixels
        Client->>Client: Encode normalized pixels without metadata
        Client->>Classifier: Classify normalized image
        alt unavailable, invalid result or disallowed
            Classifier-->>Client: Explicit error or policy rejection
        else accepted (fixture mode labeled)
            Classifier-->>Client: Score within policy
            Client->>Storage: Hash and stage normalized blob
        end
    end
```

## 4. Photograph replication

Milestone: distinct real local nodes, hash checking, retained leases. Planned: periodic repair and diverse provider placement.

```mermaid
sequenceDiagram
    participant Owner
    participant Coordinator
    participant A as Volunteer A
    participant B as Volunteer B
    participant DHT
    Owner->>Coordinator: Signed manifest, bytes, lease and target two
    Coordinator->>A: Put photo with authorization
    A->>A: Verify hash, lease, quota, persist
    A-->>Coordinator: Acknowledged provider
    Coordinator->>B: Put identical content and lease
    alt valid capacity
        B->>B: Verify and persist idempotently
        B-->>Coordinator: Acknowledged provider
        Coordinator->>DHT: Announce A and B provider records
        Coordinator-->>Owner: Two distinct replicas confirmed
    else full, unavailable or corrupted
        B-->>Coordinator: Error
        Coordinator-->>Owner: Under-replicated, retry another provider
    end
```

## 5. Discovery and image retrieval

Milestone target: actual network profile discovery and volunteer image retrieval while owner offline. Planned: selective geographic DHT indexing.

```mermaid
sequenceDiagram
    participant Bob
    participant DHT
    participant A as Volunteer A
    participant B as Volunteer B
    participant Safety
    Bob->>DHT: Discover profiles/providers
    DHT-->>Bob: Untrusted hints
    Bob->>A: Get signed profile
    A-->>Bob: Profile and credential
    Bob->>Bob: Verify owner, credential, signature, expiry
    alt invalid profile
        Bob->>Bob: Discard
    else valid profile
        Bob->>A: Get photo hash
        alt unavailable or corrupt
            A-->>Bob: Failure or invalid bytes
            Bob->>B: Fetch same photo hash
            B-->>Bob: Photo bytes
        else available
            A-->>Bob: Photo bytes
        end
        Bob->>Safety: Verify hash, decode limits and classify
        alt allowed
            Safety-->>Bob: Displayable normalized pixels
        else rejected or unavailable classifier
            Safety-->>Bob: Hide and typed failure
        end
    end
```

## 6. Like to online user

Milestone target: signed HPKE payload over actual directed RPC. No public broadcast.

```mermaid
sequenceDiagram
    participant Bob
    participant BobStore
    participant Transport
    participant Alice
    participant AliceStore
    Bob->>BobStore: Persist local positive intent
    Bob->>Bob: Validate Alice credential, encrypt and sign like
    Bob->>Transport: Directed bounded recipient-sealed parcel
    Transport->>Alice: Deliver sealed parcel
    Alice->>Alice: Open parcel and verify sender, recipient, time and signature
    alt valid and new
        Alice->>AliceStore: Transaction: dedup and inbox insert
        AliceStore-->>Alice: Commit
        Alice-->>Bob: Delivery acknowledgement
        Alice->>Alice: Show Bob in received likes before reciprocation
    else duplicate
        Alice-->>Bob: Idempotent acknowledgement
    else invalid
        Alice-->>Bob: Reject with typed error
    end
```

## 7. Offline like and later retrieval

Milestone target: durable volunteer ciphertext plus recipient retrieval. Planned production challenge freshness is tracked explicitly.

```mermaid
sequenceDiagram
    participant Bob
    participant Volunteer
    participant Disk
    participant Alice
    Bob->>Bob: Sign and HPKE encrypt like to Alice bound key
    Bob->>Bob: Seal full signed sender message inside recipient-only parcel
    Bob->>Volunteer: Deposit finite-lifetime opaque parcel
    Volunteer->>Volunteer: Validate carrier bounds, own clock and quota
    alt accepted
        Volunteer->>Disk: Persist opaque parcel and expiry
        Disk-->>Volunteer: Durable commit
        Volunteer-->>Bob: Retention acknowledgement
    else expired, full or forged
        Volunteer-->>Bob: Rejection
    end
    Note over Alice: Alice remains offline
    Alice->>Volunteer: Reconnect and authenticated mailbox poll
    Volunteer->>Volunteer: Verify proof against volunteer clock and current validity
    alt authorized poll
        Volunteer->>Disk: Read nonexpired opaque parcel
        Disk-->>Alice: Retained envelopes
        Alice->>Alice: Open parcel, verify header agreement and sender, deduplicate transactionally
        Alice->>Alice: Display received Bob like
        Alice->>Volunteer: Optional signed ack after durable processing
    else unauthorized or expired
        Volunteer-->>Alice: Reject or empty result
    end
```

## 8. Mutual matching

Milestone: domain state machine and actual positive intent exchange. Match visibility waits for both authenticated intents.

```mermaid
sequenceDiagram
    participant Alice
    participant AliceState
    participant Network
    participant BobState
    participant Bob
    Alice->>AliceState: Accept Bob received like
    AliceState->>AliceState: Incoming plus local like becomes Matched
    Alice->>Network: Persist and send signed encrypted reciprocal like
    Network->>Bob: Alice positive intent
    Bob->>BobState: Verify and apply remote positive intent
    alt existing outgoing and not blocked
        BobState->>BobState: Outgoing becomes Matched
        BobState-->>Bob: Match visible
    else duplicate
        BobState-->>Bob: No state change
    else rejected or blocked
        BobState-->>Bob: Remain rejected or blocked
    end
    Note over Alice,Bob: No automatic contact disclosure
```

## 9. Explicit external contact disclosure

Milestone target: match gate, encrypted contact payload and recipient validation.

```mermaid
sequenceDiagram
    participant Alice
    participant State
    participant Crypto
    participant Network
    participant Bob
    Alice->>State: Disclose selected external handles
    alt matched and not blocked
        State-->>Alice: Match id and peer binding
        Alice->>Crypto: Sign and encrypt match-bound disclosure
        Crypto->>Network: Recipient-only envelope
        Network->>Bob: Deliver opaque payload
        Bob->>Bob: Verify signature, recipient, match and handle limits
        Bob->>Bob: Persist and reveal selected handles
    else no match or blocked
        State-->>Alice: Unauthorized, send nothing
    end
```

## 10. Blocking and reporting

Milestone: local block and report interfaces. Planned: explicit community report transport and trusted moderation decisions.

```mermaid
sequenceDiagram
    participant User
    participant Client
    participant State
    participant Community
    User->>Client: Block profile
    Client->>State: Persist blocked state
    State->>State: Exclude candidate, refuse likes/disclosures
    Client-->>User: Local block active
    User->>Client: Report profile with bounded evidence
    Client->>State: Store private report
    alt user explicitly selects community authority (planned)
        Client->>Community: Signed evidence via private channel
        alt accepted by chosen trusted authority
            Community-->>Client: Signed expiring moderation decision
            Client->>Client: Verify policy and trust before applying
        else invalid authority or evidence
            Client->>Client: Ignore decision and expose error
        end
    else local only
        Client-->>User: Report retained privately
    end
```

## 11. Credential expiration, renewal and revocation

Milestone: explicit-time expiry and trusted revocation-set validation. Planned: fresh signed snapshot distribution and real renewal adapter.

```mermaid
sequenceDiagram
    participant Client
    participant Issuer
    participant Peer
    participant Revocation
    Client->>Peer: Signed operation and credential
    Peer->>Peer: Check now before credential expiry
    alt expired
        Peer-->>Client: Expired, operation denied
        Client->>Issuer: Reauthenticate and prove current keys
        Issuer-->>Client: Renewed signed minimized credential
    else current
        Peer->>Revocation: Consult trusted revocation state
        alt revoked or required freshness unavailable
            Revocation-->>Peer: Deny
            Peer-->>Client: Credential rejected
        else trusted current unrevoked
            Peer->>Peer: Validate operation signature and key binding
        end
    end
    Note over Issuer,Revocation: Production signed snapshots are planned
```

## 12. Photo removal, tombstones and expiration

Milestone: local lease expiration and storage removal. Planned: signed monotonic tombstone propagation and stale-record suppression.

```mermaid
sequenceDiagram
    participant Owner
    participant A as Volunteer A
    participant B as Volunteer B
    participant DHT
    participant Reader
    Owner->>Owner: Sign revisioned photo/profile tombstone
    Owner->>A: Remove owner authorization (planned distributed tombstone)
    A->>A: Verify owner and monotonic revision
    alt authorized current tombstone
        A->>A: Stop serving that owner lease
        A->>B: Propagate tombstone
        A->>DHT: Withdraw provider hint if no valid leases
    else forged or stale
        A-->>Owner: Reject
    end
    Reader->>B: Fetch expired or tombstoned content
    B->>B: Enforce validity before reading
    B-->>Reader: Not available
    B->>B: Garbage collect after final valid lease expires
    Note over Owner,Reader: Untrusted downloaded copies cannot be erased
```

