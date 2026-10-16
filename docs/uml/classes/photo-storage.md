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

Mapping: core::storage content/hash, manifest/blob/lease structs and SQLite PeerStorage; network::replication implements StorageNode/ReplicationPolicy behavior; provider metadata maps ReplicaRecord. Logical wrapper names may be type aliases. Invariants: hash verifies bytes; independent owners have distinct leases; expiry prevents reads immediately; replication success requires distinct acknowledgements. [Storage authority](../../storage.md).
