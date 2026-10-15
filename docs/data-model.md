# Domain invariants

[Contracts](contracts.md) defines boundaries; [class diagrams](uml/classes.md) define type relationships.

1. ProfileId derives from signing public key; credential subject and profile owner agree.
2. Adult credential means authoritative verified age ≥18, trusted issuer, valid version, valid signature, current validity and acceptable revocation freshness.
3. Public first name and displayed age come only from credential; no user override of verified fields.
4. Profile signature covers ordered photo manifests and expiration. Manifest byte count and hash must match bytes retrieved. A profile cannot outlive its credential.
5. Blob storage is content addressed and idempotent; shared bytes may have multiple ownership leases. Deleting one ownership lease must not erase another valid owner's lease.
6. Like belongs to sender→recipient, has authenticated positive intent, unique id and finite expiry. Only recipient decrypts.
7. Match requires both valid directional intents and neither party locally blocked/rejected. Delayed positive intent cannot undo rejection/blocking.
8. Contact disclosure is separate, explicit, match-bound, signed and recipient encrypted. Never part of public profile.
9. Blocking excludes candidates, inbox acceptance, new matches and disclosures locally. Reports are private local evidence, never automatic global bans.
10. Ranking weights and history remain local; scores never enter DHT or peer messages.
11. Expired leases/envelopes/profiles are inaccessible even before physical cleanup. Tombstones are owner authenticated and monotonic where supported.

All network identifiers are untrusted until verified. Transport node identities need not equal account keys. Separate injected time from wall clock for deterministic testing. SQL transactions protect multi-record state changes. File and database quotas must account for retained duplicates and metadata.
