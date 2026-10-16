# Network

Tokio owns asynchronous libp2p swarms. First milestone uses real TCP with Noise authentication and Yamux, or QUIC; choice recorded in [ADR](decisions/0001-foundation.md). Request/response handles directed transfers. Kademlia discovers public records/providers; binary photos and private envelopes travel by RPC. Explicit local bootstrap multiaddresses make tests reproducible. No Gossipsub like broadcasts.

A bounded actor separates swarm ownership from callers. Pending requests have deadlines, bounded concurrency and typed failures. Node configuration supplies listening addresses, bootstrap peers, data directory, byte capacity, maximum lease and connections. Structured tracing omits private payloads, keys and legal attributes. Provider failures trigger another provider; content hash is checked after transfer. Replication success counts distinct confirmed peers, not attempts.

Peer reconnects repopulate addresses and refresh provider announcements. Durable signed profiles and blobs survive restart; Kademlia in-memory routing does not imply persistent discoverability. Repair compares live acknowledgements with target replication factor. Production needs periodic jittered repair, backoff, diversity, churn testing and announcement renewal. Record implemented scope honestly in [progress](progress.md).

NAT/DCUtR, relay reservation, AutoNAT and rendezvous are planned deployment adapters. A volunteer storage node is not automatically a circuit relay; do not label it operational relay without libp2p relay behavior and tests. Direct peers learn IP addresses. Tor or equivalent privacy transport is future work. Transport encryption protects links, not public photo confidentiality or mailbox routing metadata.

[Network classes](uml/classes.md); [publication, retrieval and delivery sequences](uml/sequences.md).

M2 persistent transport identity and temporary-session behavior are defined in [key management](key-management.md) and [background sync](background-sync.md). Stable PeerId requires the same protected node data directory; endpoint addresses may change. Temporary sessions meter actual TCP stream bytes and close their swarm before returning; a phone is not advertised as a permanent provider.

M3 [application service](application-api.md) uses known volunteer profile listings for discovery without requiring candidate ids. Publication, discovery, fetch and outgoing mailbox replay use finite metered sessions and the same request/response authorization. Foreground execution does not bypass M2 peer/byte/time/concurrency bounds. A logical operation shares one budget across child requests; partial acknowledgement is durable, recipient processing remains independently verified. No global discovery/NAT/relay infrastructure is added.
