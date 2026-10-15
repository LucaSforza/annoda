# Identity and trust

CIE authoritative attributes are assumed correct. The trust boundary is issuance: normal CIE login is not a transferable peer credential. A future `VerificationService` adapter validates CIE authentication in its authorized environment, privately derives first name, age and adulthood from authoritative birth date, and asks `IdentityIssuer` to bind those facts to device signing and HPKE keys after possession challenge. Raw login responses are never forwarded as P2P proof.

DevelopmentIssuer accepts synthetic test identities only. Development trust roots are explicitly configured, never trusted by production defaults. It must not claim CIE verification. Credentials identify issuer and schema version, carry a random serial, issued/expiry times and subject keys, and are signed with Ed25519 over [canonical domain-separated bytes](protocol.md). Credential copying is harmless without subject signing private key. Profile and message signatures prove possession.

Public minimal attestation carries verified first name and adult age at issue; no birth date, surname, fiscal code or stable state identifier. Milestone credentials have a maximum 24-hour lifetime and expose `age_at_issue`, not a claim of continuously recalculated age. Short validity bounds stale age; production renewal expires no later than next birthday if exact displayed age is required. Public key is correlatable for that account. Rotation requires reissuance and defined old-key retirement, not automatic trust transfer.

Revocation strategy: issuer signs versioned, expiring serial revocation snapshots; peers trust configured issuer keys and reject revoked serials. A local trusted revoked-serial set is sufficient for initial tests; distributing signed fresh snapshots and fail-closed freshness enforcement remain mandatory before production. Expiration limits offline damage but is not immediate revocation. Record actual milestone coverage in [progress](progress.md).

Duplicate prevention is issuer-local: privately retain a keyed digest of authoritative subject id scoped to Annoda and issuer, enforce one active account, revoke old credential on replacement. Never publish digest or government id. Multiple issuers require a privacy-preserving coordination agreement or accept cross-issuer duplicates; no claim of solved global uniqueness. Retention and recovery procedures require separate policy. CIE authority is trusted; misuse of a stolen device key remains a threat.

See [registration and renewal sequences](uml/sequences.md) and [identity classes](uml/classes.md).
