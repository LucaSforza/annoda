# Likes, matching and contacts

Received likes are visible to their recipient before reciprocation. Storage peers and unrelated accounts cannot read sender payload or contacts. HPKE encryption complements sender signature and credential key binding. [Protocol](protocol.md) owns envelope validation and replay rules.

| State | Event | Next state |
|---|---|---|
| Neutral | local like | Outgoing |
| Neutral | authenticated remote like | Incoming |
| Outgoing | authenticated remote like | Matched |
| Incoming | local accept/like | Matched |
| Incoming | reject | Rejected |
| Neutral/Outgoing | local pass | Rejected |
| Any | local block | Blocked |
| Any | duplicate same intent | unchanged |
| Rejected/Blocked | delayed like | unchanged/rejected |
| Matched | explicit contact disclosure | Matched + private disclosure |
| Other | contact disclosure | error |

No negative remote event can forge a user's positive intent. Local API derives owner from account, not caller-supplied sender. Persist sent intent before publishing; persist incoming verified event and dedup marker transactionally. A match id deterministically binds ordered participants and positive-intent evidence, with no global match feed. Peers independently recognize match when each learns both intents; an acknowledgement without signed intent is insufficient.

Pass is local and private. Rejecting a like prevents delayed re-creation; expiry of a message must not silently erase rejection. Unmatch, unblock and re-like semantics require future explicit transitions and migration. Do not add undocumented flags that reinterpret existing states.

ContactHandle supports Instagram, Telegram, WhatsApp and Other(service,value), validates bounded nonempty values, and remains encrypted to matched peer. Disclosure payload binds match/participants and selected handles; never auto-share saved contacts. Each side chooses independently. Blocking stops further local disclosures. Deletion cannot retract already revealed external handles. Signed moderation decisions and reports do not create matches.

[Class model](uml/classes.md), [online/offline/match/disclosure sequences](uml/sequences.md).
