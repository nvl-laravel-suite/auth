# Flows

Complete password login calls Authentication::login with explicit credential/context arrays, StatefulGuard and Session. Passwordless/social consumers establish a session only after the native proof succeeds. Owner intent consumption selects an owner once; membership and current availability still decide admission. Invitation acceptance/register, password reset, TOTP, recovery-code and passkey services retain their transaction and replay boundaries.
