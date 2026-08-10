# Verification reference

- Normalize the recipient before hashing.
- Scope a challenge hash by purpose and message type.
- A compound challenge may carry a primary token and secondary numeric code;
  hash them independently and consume the entire row when either succeeds.
- Token callbacks must carry the challenge UUID for direct lookup. Never scan
  active challenges to locate a token-only callback.
- Store plaintext secrets nowhere; return them only at issuance or in the
  after-commit delivery event.
- Lock consumption and commit the wrong-attempt counter before throwing.
- Reject consumed, revoked, expired, and attempt-exhausted state.
- Treat provider email as a claim, never provider ownership. Preserve its
  verified boolean and claim provenance, and fail closed before email matching.
- Use `AuthSubjectResolver` only after a proof has succeeded.
- Regenerate Laravel's session identifier after authentication.
- Run shared eligibility and login pipelines before success metadata.
- Require every `AuthDeliveryRequest` feature/message pair to match the closed
  package-owned delivery map.
- Delivery listeners own templates, transport, retries, expiry rechecks, and
  idempotency by `messageId`.
