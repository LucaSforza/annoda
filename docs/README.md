# Annoda knowledge base

This KB is the normative specification of intended behavior. Annoda now has a verified local Rust vertical slice; see [delivered scope and checks](progress.md). Code records delivered behavior; [progress](progress.md) records evidence and gaps. Requirements marked **planned** remain requirements, not claims of implementation. No prototype should be represented as a production dating service.

Start with [vision](vision.md), [architecture](architecture.md), [contracts](contracts.md), [security](security.md), and [testing](testing.md). Changes to contracts and their [UML](uml/README.md) precede implementation. Conflicts require an explicit ADR and migration, never silent divergence.

| Concern | Authority |
|---|---|
| Public entities and invariants | [Data model](data-model.md) |
| Serialization, authentication, resource bounds | [Protocol](protocol.md) |
| Trust anchors and CIE boundary | [Identity](identity.md) |
| Connectivity and discovery | [Network](network.md) |
| Photo availability and deletion | [Storage](storage.md) |
| Positive intent and disclosure | [Matching](matching.md) |
| Private learning and evaluation | [Ranking](ranking.md) |
| Image handling and inference boundary | [Photo moderation](photo-moderation.md) |
| Threat analysis | [Security](security.md) |
| Exposure and retention | [Privacy](privacy.md) |
| Native integration | [Mobile integration](mobile-integration.md) |
| Executable acceptance | [Testing](testing.md) |
| Tradeoffs and dependency evidence | [ADR index](decisions/README.md) |
| Implementation tracking | [Progress](progress.md) |
| Reusable agent workflow | [KB skill](skills/annoda-kb/SKILL.md) |
