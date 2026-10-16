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

Mapping: network PeerNode actor, libp2p identity NodeIdentity, Kademlia PeerDiscovery, request/response Transport; core protocol MessageEnvelope, SQLite PeerStorage. RelayNode is planned libp2p circuit-relay adapter, not storage forwarding. Invariants: account identity independent of transport; bounded queues/frames; RPC authentication independent of Noise connection. [Network](../../network.md).
