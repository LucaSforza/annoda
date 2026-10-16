# Discovery and validated photograph retrieval

Status: M3 contract before implementation, [progress](../../progress.md) records actual proof.

```mermaid
sequenceDiagram
actor Host
participant Client
participant Peers as Known volunteers
participant DB
participant Safety as PhotoProcessor
Host->>Client: discover(age filter, bounded cursor)
Client->>Peers: bounded ListProfiles
Peers-->>Client: signed profiles
Client->>Client: verify issuer, signatures, expiry, revision and local eligibility
Client->>DB: cache newest verified profiles and stable page state
Client-->>Host: candidate summaries and manifests
Host->>Client: fetch photo(owner, hash)
Client->>Client: verify current owner manifest authorization
loop known providers within shared budget
Client->>Peers: fetch authorized content
Peers-->>Client: bounded bytes or failure
Client->>Safety: hash, length, format, decoding and incoming classification
alt valid and accepted
Safety-->>Client: display-ready photograph
else corrupt, unavailable or rejected
Client->>Client: try next provider or return typed failure
end
end
Client-->>Host: validated bytes only
```

Participants map to `annoda_network::client::AnnodaClient`, core `PeerStorage`/`AccountKeyStore`, intelligence `PhotoProcessor` and existing finite libp2p volunteer RPCs. Native UI and real CIE adapters remain planned. [Application contract](../../application-api.md), [operation contract](../../durable-operations.md).
