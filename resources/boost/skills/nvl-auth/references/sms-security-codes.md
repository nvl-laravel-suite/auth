# SMS security-code reference

NVL Auth produces a transport-neutral security-code delivery request. The host
listener decides whether the normalized recipient is an SMS number, email
address, or another destination.

Recommended host rules:

- configure 6-8 digits and a short expiry;
- rate-limit issuance by destination and network context;
- deduplicate delivery by `messageId`;
- never put the code in logs, URLs, analytics, or audit metadata;
- recheck `security_codes` admission and `expiresAt` before sending;
- use one generic request/verification response to reduce enumeration;
- treat SMS as phishable and vulnerable to number takeover;
- do not count two codes sent to the same destination as independent MFA roots.

Auth commits attempt counters and one-time consumption. Provider retries,
delivery callbacks, opt-out handling, and telecom policy belong to the host
delivery package.
