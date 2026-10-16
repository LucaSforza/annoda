# Threat model — before networking

Trust CIE identity facts completely. Trust only explicitly configured credential issuers for signed attestations. Assume malicious users, providers, observers and arbitrary network input. A development issuer is not a production trust root. Protect account secrets, private likes/contacts, local preferences, integrity of profiles and availability within volunteer limits.

| Threat | Required mitigation | First milestone boundary |
|---|---|---|
| Forged profile, credential copying | issuer signature, subject key binding, owner proof | core tests |
| Tampered message, impersonation | Ed25519 domain-separated signatures and Noise/QUIC | core/network tests |
| Replay or duplicate intent | signed id/time, transactional persistent dedup | persistence tests |
| Private likes/contact leakage | RFC 9180 recipient encryption, explicit match gating | no chat |
| Malicious provider/corruption | hash/manifest verification, fallback | local provider tests |
| Storage abuse/DoS | bounded frames, queues, leases, disk, connections | per-IP rate policy and bandwidth may be deferred |
| Harvesting/enumeration | minimal public metadata, optional future selective discovery | public photos remain harvestable |
| IP/location correlation | coarse opt-in geography, no precise coordinates | direct IP visible; anonymity transport planned |
| Fake photos | classifier only detects policy categories | no biometric ownership claim |
| Spam from verified adult | recipient block, quotas | distributed rate reputation planned |
| Stale/revoked credentials | finite validity, revocation set | authenticated snapshot distribution planned |
| Preference leakage | no weights/logs in protocol | device compromise out of scope |
| Unauthorized mailbox fetch/delete | recipient challenge signature, nondestructive idempotent poll | enforce before deployment |
| Profile rollback/resurrection | monotonic revision and signed tombstones | must record implementation gaps |
| Stolen local secrets | memory-only or encrypted store; mobile platform keystore adapter | recovery/rotation planned |

Use OS cryptographic RNG. No homemade encryption; standardized HPKE suite and maintained libraries. Sign exact deterministic bytes with per-purpose context. Validate before expensive work; reject unknown version/algorithm. Never log raw legal identity, private payloads, credentials or secret keys. Tests use synthetic identities only.

Before Internet deployment: independent cryptographic review, fuzz parsers, signed fresh revocation, replay-safe retrieval, cross-process quotas, per-peer bandwidth/rate caps, revocation/key rotation/recovery, NAT/relay and mobile lifecycle tests, production inference, abuse operations and privacy/legal review. These are concrete release gates, not claims of implemented protection. [Progress](progress.md) must name residual gaps.

## M2 threats and release boundaries

[Key-management contract](key-management.md) covers offline vault guessing, corrupted/replaced files, hostile KDF parameters, filesystem permissions/symlinks, atomic creation and cross-process locks. Do not claim password recovery or file rollback prevention. Headless transport plaintext mode explicitly trusts operator filesystem/volume protection; account vaults stay encrypted. Unlocked process memory and sensitive SQLite remain exposed to same-user/device compromise.

[Sync](background-sync.md) adds malicious length/bandwidth exhaustion, peer fanout, cancellation/crash windows and notification replay threats. Meter before I/O exceeds allowance, authenticate/decrypt before state, commit outbox/replay/checkpoint together and require explicit host ack. No launch-time/remote-availability guarantees. Only native host supplies power/radio conditions; background authorization unavailable means defer. Physical Keychain/Keystore integration and OS testing remain planned.

## M3 application boundary

[Application API](application-api.md) treats signed records and saved operations as untrusted until validated. Credential import binds both restored public keys; sender summaries originate from verified delivery, never an unsigned hint. Discovery cache replacement checks signed revisions. Unknown/foreign pagination cursors and operation versions fail explicitly. Required photo inference unavailable fails closed, including cached display paths. Reports are private signed evidence with no implied community acceptance.

Durable operation replay must not create new random likes, leak contacts through public metadata, resurrect blocked interactions or claim delivery from retention acknowledgements. Block and cancellation are different: block terminates prohibited pending work; cancellation retains authorized pending work for recovery. Existing deduplication, short transactions and notification idempotency remain mandatory. Account vault and session ownership serialize authorized state changes; process termination can occur between every remote response and local checkpoint. No distributed atomicity or exactly-once remote processing is claimed.

Local profiles, normalized cache, recipient credentials, contacts, reports, outgoing ciphertext and preference snapshots have bounded storage but remain sensitive SQLite/filesystem data. The encrypted vault does not encrypt these records. Device compromise, rollback, stale issuer revocation distribution, public-photo harvesting, traffic analysis and spam remain unresolved production risks. No new public location fields, centralized backend or moderation authority are introduced.
