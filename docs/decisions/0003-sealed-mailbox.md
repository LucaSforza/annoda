# ADR 0003: conceal sender and intent from mailbox volunteers

Status: accepted during contract review before network vertical-slice implementation.

Context: encrypting only the inner payload while exposing sender credential, recipient and Like kind reveals who-liked-whom. This defeats the intended privacy despite cryptographically unreadable payload bytes.

Decision: RPC deposit and volunteer persistence use a recipient-sealed MailboxParcel containing the complete sender-authenticated StoredMessage. Public carrier fields are version, random id, recipient, issuance/expiration and HPKE ciphertext; header is authenticated as associated data. Distinct mailbox context avoids cross-purpose confusion. Recipient validates outer/inner agreement, issuer, sender signature, expiry and replay before applying intent.

Consequences: volunteers validate bounded opaque retention, not hidden account credentials. This increases anonymous spam pressure, mitigated initially by capacity/per-recipient/bandwidth limits; stronger privacy-preserving rate tokens are planned. Transport timing/IP remains exposed. Inner and outer HPKE are deliberately nested in the initial version to reuse tested inner signatures/key binding; a later single-layer carrier requires migration and golden vectors. No novel primitive is introduced.

Alternative rejected: exposing sender identity and explicit like kind as metadata while claiming like confidentiality. A transport identity remains independently generated and must not be treated as the hidden account.
