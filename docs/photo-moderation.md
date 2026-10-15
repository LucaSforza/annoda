# Local photograph validation

Outgoing: bound compressed bytes → decode approved JPEG/PNG with allocation/dimension limits → reject invalid/oversized dimensions → re-encode decoded pixels without unnecessary metadata → classify normalized pixels → reject score above configured threshold → hash normalized bytes → create signed manifest. Incoming: bound bytes → verify content hash and declared length → decode with same limits → classify before display. Re-encoding is not proof that photo depicts credential owner.

PhotoSafetyClassifier returns finite probability in [0,1] or explicit unavailable/error; invalid threshold or nonfinite result fails closed. Interface permits ONNX Runtime or native Core ML/Android backends. Model licensing, checksum, preprocessing, calibration and device benchmark must be reproducible before claiming real safety. Do not train a new classifier for milestone.

Deterministic test classifier exists solely for tests/simulations. Prototype must visibly mark this mode and cannot claim real NSFW filtering. Production publishing/display must fail if real classifier unavailable; callers must opt into development fixtures explicitly. Signed protocol authentication does not guarantee semantic image safety. Incoming verification must happen in client display path, even if volunteer previously inspected bytes.

Local blocking excludes target and rejects new local interaction. Profile reports retain bounded signed evidence privately and may be explicitly sent to chosen community authority in future. ModerationDecision binds issuer, subject, policy version, reason, creation/expiry and signature; trust policy is configurable and separate from identity authority. No automatic global ban service.

App-store operation additionally needs actual model, abuse/report handling, legal/privacy review, child-safety procedures and response operations. These are not satisfied by a Rust trait or mock classifier. See [security](security.md), [sequences](uml/sequences.md).

## Moderation adapter contract

A local report is bounded private evidence: random report id, reporting account, subject profile id, policy reason and evidence content hashes; no raw government attributes. It does not itself ban or broadcast a profile. `ModerationDecision` is a versioned record with authority key/id, subject account, policy version, bounded reason, issue/expiry and signature. A `ModerationDecisionVerifier` interface accepts explicitly trusted community authority keys and current time, returning verified decision or typed error. Community trust is separate from identity issuers. Initial interface may be supplied without a backend or real signature implementation; unavailable verification must not apply a ban. Report submission and authenticated authority operations remain planned unless evidence says otherwise.
