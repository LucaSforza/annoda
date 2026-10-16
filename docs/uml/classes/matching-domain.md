## C. Matching

```mermaid
classDiagram
    class Like {
        +String id
        +ProfileId sender
        +ProfileId recipient
        +u64 expires_at
    }
    class Pass {
        +ProfileId candidate
        +u64 created_at
    }
    class LikeInbox {
        +receive(envelope) Result
        +list() List
        +accept(sender) MatchState
        +reject(sender) Result
    }
    class Match {
        +ProfileId first
        +ProfileId second
        +MatchState state
        +apply(event) Result
    }
    class MatchState {
        <<enumeration>>
        Neutral
        Outgoing
        Incoming
        Matched
        Rejected
        Blocked
    }
    class ContactHandle {
        +String service
        +String value
    }
    class ContactDisclosure {
        +String match_id
        +ProfileId sender
        +ProfileId recipient
        +encrypt_for_recipient() Envelope
    }
    LikeInbox "1" *-- "0..*" Like
    Match "1" --> "2" Like : valid positive evidence
    Match "1" *-- "1" MatchState
    Pass ..> Match : prevents matching
    ContactDisclosure "0..*" --> "1" Match : requires matched state
    ContactDisclosure "1" *-- "1..*" ContactHandle
```

Mapping: core::matching structs/enums and SQLite inbox/state service. LikeInbox and Match may be service/record combinations; MatchState is enum; Pass can map private state transition. Invariants: sender authenticated, recipient alone decrypts, duplicates do not reapply, rejection/blocking cannot be bypassed by delay, contacts gated separately. [State table](../../matching.md).
