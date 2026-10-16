# ADR 0005: finite shared sync operation and transactional notification outbox

Status: accepted before M2 implementation.

Decision: reuse annoda-network/core for one foreground/background operation, node-owned deadline/cancellation, raw TCP transfer metering, bounded known-peer attempts and persisted checkpoints. No extra service crate, mobile platform dependency, push gateway or continuous background daemon. Persistent keys must pass restoration tests before service implementation begins.

Cancellation uses maintained Tokio [`CancellationToken`](https://docs.rs/tokio-util/latest/tokio_util/sync/struct.CancellationToken.html) from tokio-util 0.7 rather than a custom signaling protocol. Session transport accounting uses one short mutex-protected synchronous poll, shared by all connections and optional transfer phases; no mutex is held across an await.

Append optional paged mailbox RPC/response variants without modifying M1 encodings or signed crypto records. New code continues to handle old PollMailbox; peers without paging are reported as unsupported/deferred (a bounded legacy first-page fallback may be explicit). This capability extension does not imply a blanket protocol redesign or universal old-peer completion guarantee. SQLite changes are additive tables/indexes; preserve existing match/blob/lease data.

Outbox events commit with authenticated local state/checkpoint. Stable opaque ids and explicit host ack provide at-least-once adapter delivery; platform request ids coalesce crash retries. No exactly-once display claim. Settings suppress notifications without suppressing verified matching state. SyncReport lists newly created events; separate durable pending reads recover crash windows.

M2 voluntary cooperation is finite forwarding of already authorized replica batches to available volunteers, bounded by native conditions/time/bytes/allocation and shared session budgets. No inbound phone provider/durable promise without explicit future tests.

Consequences: offline/expired/revoked/cancelled sessions can return partial or deferred results while preserving commits. OS scheduling, NAT and peer overlap remain availability limits. Raw TCP accounting includes encrypted transport/control traffic but excludes lower network headers/kernel buffering. CPU/storage checkpoints need small non-preemptible finalization tolerance. Physical native lifecycle/security tests remain future proof.
