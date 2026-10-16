# Agent instructions

## Quality and safety

- Make the smallest coherent implementation. Keep it clear, maintainable, and consistent with nearby code. Explain non-obvious mechanics briefly beside the implementation.
- Keep public APIs narrow. Validate untrusted input and report typed errors; do not silently swallow failures.
- Never expose or log secrets, API keys, tokens, private payloads, legal identity data, or private contact data. Keep account secret keys in memory or a protected encrypted store; do not add plaintext key files.
- Prefer safe Rust. Do not use `unsafe`, production `unwrap`/`expect`, or homemade cryptography.
- Match the normative KB and record actual coverage and gaps. Do not describe planned behavior as delivered.
- Record architectural tradeoffs and incompatible changes in an ADR; do not silently diverge from the contract.

## Annoda KB workflow

1. Resolve repository root from `docs/skills/annoda-kb/`; begin with [README](docs/README.md) and [progress](docs/progress.md), then read only the authoritative concern documents linked there.
2. Treat the KB as intended behavior and progress as evidence. Check the applicable contracts, invariants, security model, and acceptance criteria before changing behavior.
3. Before behavior changes, update the affected contract, invariant, matching UML class/sequence diagram, and migration ADR when compatibility changes.
4. Preserve signature and credential subject binding, encrypted recipient routing, lease expiry, and positive-consent matching boundaries across layers.
5. Write a failing regression or acceptance test before implementation. Follow the file-search tool requirement below.
6. Coordinate shared contracts before delegation; the principal owns architecture and documentation. Implementation agents may change Rust after the contracts exist.
7. After implementation, run the checks in `docs/testing.md`; include real local network acceptance for network changes. Record exact commands, results, limitations, and deferred adapters in `docs/progress.md`.
8. Keep development credentials and deterministic classifiers visibly nonproduction. A generated binding does not prove execution in a native runtime. When the KB conflicts with implementation, determine which is wrong; never silently edit the KB to bless an unsafe change. Preserve compatibility unless an ADR defines migration.

Do not grant broader permissions or add unrelated review gates.

The volunteer node's M2 transport identity is filesystem-protected plaintext under its private data directory, as specified in [key management](docs/key-management.md). This exception never applies to account keys; do not describe the node key as encrypted at rest.

## File search

Use the FFF MCP tools for all file search operations. Use `find_files` to locate files and `grep`/`multi_grep` to search file contents. Read the identified files directly after locating them; do not substitute shell `find`, `grep`, or `rg` for FFF searches.

## Rust workspace

Use Rust 2024. Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, and `cargo build --workspace` after implementation changes. Keep `Cargo.lock` committed for applications and the complete workspace.
