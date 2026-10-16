# Bounded opportunistic synchronization (M2)

Authority for application sync lifecycle. [Key management](key-management.md), [notifications](notifications.md), [contribution](peer-contribution.md), [protocol](protocol.md), [matching](matching.md) own their respective rules. See [M2 UML](uml/m2.md).

## Boundary and ownership

One `sync_once` service in annoda-network is reused for foreground and background. No central server/push service, indefinite daemon or separate background wire protocol. Phase C implementation starts only after persistent account and transport tests pass. Existing core/network crates are reused.

`SyncContext` supplies an authorized existing account handle, its current credential, trusted issuers/revocations, persistent client-state path, known bootstrap peers, injected trusted clock, node configuration and optional contribution inputs. Account opening/unlock is a separate bounded cryptographic operation before networking; an unavailable/locked handle returns a typed deferred/key error. Sync never creates a new account. Native host must arrange an authorized backend that is usable in its current execution context. Passphrase acquisition/KDF is not an interruptible network operation.

A session owns a temporary swarm with its separately persisted transport identity. A per-account/process lock prevents simultaneous sessions mutating the same owner state; return Busy rather than race foreground/background sessions. Restoration, database ownership and cleanup errors are explicit. A failure/cancellation drops sockets and waits for swarm shutdown before releasing session resources. No database transaction remains open across network awaits. Event processing/checkpoint commits use short transactions. Keys held by a running session are released when it terminates; locking an account must cancel/drain active work before claiming all in-process key access is released.

## Algorithm

1. Verify unlocked account matches credential, issuer and time. Open existing local state and load per-peer mailbox cursor/checkpoints.
2. Select at most max_peers distinct known/reachable bootstrap targets. Connect only allowed selected peers; prevent autonomous Kademlia dialing beyond this session allowlist.
3. Poll bounded mailbox pages using existing recipient proof. Validate carrier header, decrypt parcel, validate sender credential/signature/bindings/time, then ingest supported Like or ContactDisclosure. One malicious parcel cannot silently mutate state or prevent all later eligible items from being attempted.
4. In one transaction per item, persist authenticated intent/contact, replay marker, derived match, new notification outbox entries and checkpoint. Duplicate valid input is a no-op; invalid input advances only an explicit rejection/checkpoint marker and increments typed rejection diagnostics. Cancellation before commit retries safely; after commit the durable event remains.
5. Optional contribution runs only under [policy](peer-contribution.md) with remaining budgets. Retry only boundedly. No response/replica acknowledgement is fabricated.
6. Return structured report with status, counts, verified newly created opaque event ids, transfer usage, contacted peers and deferred/rejection reasons. Persist progress. Close swarm even when timeout/cancel occurs. No acknowledgement of OS notification display is implied.

Complete/Partial/Deferred/Cancelled/BudgetExhausted outcomes are explicit. Offline/no peers returns promptly with no state loss/spin. Partial results preserve committed events; expected offline/cancellation is not a raw internal error. Invalid configuration and wrong/expired credentials fail before network work. Report may contain only opaque event ids and numerical/reason codes, no credentials, plaintext contacts or ciphertext.

Rejection bookkeeping is bounded at 8192 rows per owner and expires with the rejected parcel. Local storage/outbox capacity or database failures defer the item without advancing its checkpoint: a rolled-back valid intent must remain retryable. Cleanup of expired rejection markers never removes verified matching evidence or pending notification events.

M2 sync registers selected addresses with the swarm's directed RPC routing only. Its Kademlia table remains empty and it starts no Kademlia queries, avoiding automatic/periodic bootstrap fanout. Normal volunteer nodes retain their Kademlia discovery behavior. Discovering new bootstrap targets for a later session remains host/configuration work; this finite service does not claim unrestricted discovery within a mobile window.

Session Annoda RPC supports outbound requests only; replies arrive on their corresponding request streams. A selected peer cannot open an unsolicited incoming Annoda request and allocate its advertised blob frame. Normal volunteers retain bidirectional service support. The application request ceiling covers initiated Annoda RPCs; transport/control traffic remains covered by shared byte and connection limits.

## Resource enforcement

`SyncBudget`: positive bounded max_duration, max_download_bytes, max_upload_bytes, max_peers, max_mailbox_items, max_concurrent_requests, request_timeout, retries; optional replica allocation is further capped by contribution policy. Public input limits prevent huge allocations. A zero item/transfer budget means no corresponding work; invalid duration/concurrency is rejected or returns exhausted predictably. Hard upper bounds on input peer lists and retries prevent caller-triggered unbounded work.

Count actual transport bytes at the raw TCP I/O boundary, including Noise/Yamux/Kademlia overhead, across all session connections; never accept a whole oversized response and count afterward. Before each read/write, restrict buffer to remaining allowance; stop when exhausted. Counters are shared safely across connections and record actual completed I/O, not advertised blob sizes. Keep the existing 8 MiB per-RPC bound checked before payload allocation as a second defense. Transport counters exclude kernel/IP/TCP packet headers and bytes buffered externally after closure; do not call this a radio billing cap.

Deadline and cancellation cover connect, poll, retry and optional transfer waits and final shutdown. Stop requests promptly; avoid waiting a full request timeout after cancellation. Sync database opening and transactions use a busy-wait timeout no greater than the remaining window or 25 ms, rather than inheriting the general store's five-second timeout. Cooperative CPU/SQLite commits cannot be preempted mid-instruction/transaction, so allow a documented small finalization tolerance, not a guarantee against OS process suspension or a stalled filesystem. No sleeps/backoff extend beyond remaining deadline. Request concurrency never exceeds the configured ceiling (initial serial scheduling is valid); timed-out requests must finish or be drained before their retry can consume another concurrency slot. Retry count means additional attempts, never infinite retries. Optional replica work must fit remaining time/bytes/storage and explicit host permission.

## Mailbox paging compatibility

Keep old RPC encodings/indices unchanged. Append `PollMailboxPage` and `MailboxPage` variants as an additive capability for M2; signed credential/envelope/parcel bytes do not change. Page cursor is `(expires_at, parcel_id)` in existing stable order, opaque to native UI. Explicit pagination makes later items reachable under small per-run budgets. Persist last committed item cursor; reset to start after a completed scan so newly inserted earlier entries are eventually visited. Old peers may reject the new optional RPC; report UnsupportedPeer/deferred, or use a documented bounded first-page fallback. Never claim all messages synchronized from an unsupported peer. See [ADR 0005](decisions/0005-sync-outbox.md).

## Scheduling limits

Native host supplies OS execution window, network/battery conditions and notification permissions. No fixed period or wakeup guarantee. NAT/firewalls, vanished providers and lack of simultaneous reachability can prevent useful work. No durable provider announcement is made for an unavailable phone. Platform guidance/examples are in [mobile integration](mobile-integration.md); real native task scheduling and physical-device validation remain outside the Rust-only implementation proof.
