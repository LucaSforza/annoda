# Normative UML

Mermaid diagrams specify intended behavior, not delivery claims. Update affected diagrams before changing implementation; actual evidence lives in [progress](../progress.md). Every standalone file below contains one Mermaid diagram plus its invariants, Rust mapping, and implementation status.

## Class diagrams

- [Identity and account](classes/identity-account.md)
- [Photographs and distributed storage](classes/photo-storage.md)
- [Matching](classes/matching-domain.md)
- [Network](classes/network-domain.md)
- [Ranking](classes/ranking-domain.md)
- [M2 identity ownership](classes/m2-identity-ownership.md)
- [M2 bounded synchronization](classes/m2-bounded-synchronization.md)
- [M2 transactional notifications](classes/m2-transactional-notifications.md)

## Sequence diagrams

- [Registration and CIE credential issuance](sequences/registration-cie-issuance.md)
- [Profile creation and publication](sequences/profile-creation-publication.md)
- [Local photo validation](sequences/local-photo-validation.md)
- [Photograph replication](sequences/photograph-replication.md)
- [Profile discovery and image retrieval](sequences/profile-discovery-retrieval.md)
- [Like to online user](sequences/online-like.md)
- [Offline like retrieval](sequences/offline-like-retrieval.md)
- [Mutual matching](sequences/mutual-matching.md)
- [External contact disclosure](sequences/external-contact-disclosure.md)
- [Blocking and reporting](sequences/blocking-reporting.md)
- [Credential expiration, renewal and revocation](sequences/credential-expiration-renewal.md)
- [Photo removal and expiration](sequences/photo-removal-expiration.md)
- [M2 first account creation](sequences/m2-first-account-creation.md)
- [M2 account restoration](sequences/m2-account-restoration.md)
- [M2 OS-triggered synchronization](sequences/m2-os-triggered-sync.md)
- [M2 offline like notification](sequences/m2-offline-like-notification.md)
- [M2 peer contribution](sequences/m2-peer-contribution.md)
- [M2 sync cancellation and recovery](sequences/m2-sync-cancellation.md)
- [M2 volunteer restart](sequences/m2-volunteer-restart.md)

## Compatibility indexes

The original aggregate pages retain their headings and fragment anchors as forwarding indexes: [classes](classes.md), [sequences](sequences.md), and [M2 diagrams](m2.md). Keep these indexes when adding diagrams so existing KB links remain valid.

## Adding diagrams

For M3 and later, create one Markdown file per Mermaid diagram under `classes/` or `sequences/`. Use a descriptive, stable filename; prefix milestone-specific diagrams when needed. Preserve the diagram's natural-language invariants, Rust mapping, and implemented/planned status beside it. Add the new file to this index and add its heading plus forwarding link to the corresponding compatibility index. Do not collect multiple diagrams in one file.

## M3 application service

[Application classes and interactions](m3.md) extend the split M1/M2 diagrams without changing their signed protocol contracts.

- [M3. Application service and owned state](classes/m3-application.md)
- [M3. Durable operations and query DTOs](classes/m3-operations.md)
- [M3. Account creation and credential import](sequences/m3-account-import.md)
- [M3. Publication with partial replication](sequences/m3-profile-publication.md)
- [M3. Discovery and validated photograph retrieval](sequences/m3-discovery-photo.md)
- [M3. Durable like and asynchronous delivery](sequences/m3-like-delivery.md)
- [M3. Incoming like before match](sequences/m3-incoming-like.md)
- [M3. Reciprocal positive intent](sequences/m3-mutual-match.md)
- [M3. Explicit matched contact disclosure](sequences/m3-contact-disclosure.md)
- [M3. Restart and operation recovery](sequences/m3-restart-recovery.md)
- [M3. Blocking and rejected interactions](sequences/m3-blocking.md)
