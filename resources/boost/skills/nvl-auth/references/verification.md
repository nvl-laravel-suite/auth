# Verification reference

- Normalize the recipient before hashing.
- Scope a challenge hash by purpose and message type.
- Store plaintext secrets nowhere; return them only at issuance or in the
  after-commit delivery event.
- Lock consumption and commit the wrong-attempt counter before throwing.
- Reject consumed, revoked, expired, and attempt-exhausted state.
- Treat provider email as a claim, never provider ownership.
- Use `AuthSubjectResolver` only after a proof has succeeded.
- Regenerate Laravel's session identifier after authentication.
- Delivery listeners own templates, transport, retries, expiry rechecks, and
  idempotency by `messageId`.
