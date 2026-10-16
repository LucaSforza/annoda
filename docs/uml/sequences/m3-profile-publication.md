# Publication with partial replication

Status: M3 contract before implementation, [progress](../../progress.md) records actual proof.

```mermaid
sequenceDiagram
actor Host
participant Client
participant Safety as PhotoProcessor
participant DB
participant V1 as Volunteer 1
participant V2 as Volunteer 2
Host->>Client: publish photos under budget
Client->>Safety: decode, normalize, classify and hash
alt safety unavailable or rejected
Safety-->>Client: typed failure
Client-->>Host: no signed publication
else accepted
Client->>DB: commit next revision, exact bundle and Pending operation
Client->>V1: signed profile and authorized blobs/leases
V1-->>Client: durable acknowledgements
Client->>DB: checkpoint distinct per-item acknowledgements
Client->>V2: same immutable bundle
alt V2 available
V2-->>Client: acknowledgements
Client->>DB: mark Completed
else unavailable or cancelled
Client->>DB: retain Partial and pending content
end
Client-->>Host: receipt with confirmed peers and remaining work
end
```

Participants map to `annoda_network::client::AnnodaClient`, core `PeerStorage`/`AccountKeyStore`, intelligence `PhotoProcessor` and existing finite libp2p volunteer RPCs. Native UI and real CIE adapters remain planned. [Application contract](../../application-api.md), [operation contract](../../durable-operations.md).
