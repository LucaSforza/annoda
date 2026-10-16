# Blocking and rejected interactions

Status: M3 contract before implementation, [progress](../../progress.md) records actual proof.

```mermaid
sequenceDiagram
actor Host
participant Client
participant DB
Host->>Client: block(profile id)
Client->>DB: atomic terminal Blocked and cancel pending likes/disclosures
Client-->>Host: persisted local block
Host->>Client: discover
Client-->>Host: blocked profile excluded
Host->>Client: like or disclose contacts to blocked profile
Client-->>Host: Unauthorized, no remote operation
Host->>Client: create bounded signed report
Client->>DB: persist local report
Client-->>Host: LocalOnly capability
Host->>Client: submit report remotely or delete globally
Client-->>Host: Unsupported
```

Participants map to `annoda_network::client::AnnodaClient`, core `PeerStorage`/`AccountKeyStore`, intelligence `PhotoProcessor` and existing finite libp2p volunteer RPCs. Native UI and real CIE adapters remain planned. [Application contract](../../application-api.md), [operation contract](../../durable-operations.md).
