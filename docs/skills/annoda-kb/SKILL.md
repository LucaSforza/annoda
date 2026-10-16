---
name: annoda-kb
description: Maintain Annoda protocol knowledge base, contracts, UML and evidence when changing Annoda architecture or Rust behavior.
---

# Annoda KB workflow

Resolve repository root from this skill at `docs/skills/annoda-kb/`; start with `../../README.md` and `../../progress.md`. The KB specifies intended behavior; progress records delivered proof. Root AGENTS.md specifies workflow. Do not treat planned diagrams as operational claims.

Read only authoritative concern documents linked by KB index. Before behavior changes, update affected contract, invariant, corresponding class/sequence diagram and migration ADR if incompatible. Keep signatures, credential subject binding, encrypted recipient routing, lease expiry and matching consent rules consistent across boundaries. Link rather than duplicate normative rules.

For persistent accounts or node identities, route to `../../key-management.md` and `../../identity.md`. For finite foreground/background work, use `../../background-sync.md`, `../../peer-contribution.md` and `../../notifications.md`; native scheduling belongs in `../../mobile-integration.md`. Their class and interaction mappings live in `../../uml/m2.md`. Preserve create/open separation, exact key restoration, atomic state/event/checkpoint commits and actual resource enforcement; configuration fields alone are not proof. Do not confuse filesystem-protected plaintext transport keys with encrypted account vaults.

Write a failing regression/acceptance test before implementation. Follow repository file-search tool requirements. Coordinate shared contracts before delegation; principal owns architectural decisions and docs. Implementation agents change Rust after contracts exist. Do not grant broader permissions or require unrelated review flows.

After implementation, run required checks from testing.md and actual network acceptance for network changes. Record exact verified behavior, commands, failures and deferred adapters in progress.md. Development credentials and deterministic classifiers must remain visibly nonproduction. A generated mobile binding is not proof of native runtime execution.

When contradictions arise, inspect code/tests and decide whether implementation bug or proposed contract change; never silently rewrite KB to bless unsafe behavior. Preserve compatibility unless migration ADR defines transition.
