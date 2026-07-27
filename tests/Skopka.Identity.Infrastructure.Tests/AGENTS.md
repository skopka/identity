# Infrastructure Test Instructions

Read `../../AGENTS.md` and `../../src/Skopka.Identity.Infrastructure/AGENTS.md` first.

Credential tests must cover verifier format handling, wrong passwords, parameter
upgrades, pepper rotation and malformed/untrusted verifier input. Reduced work factors
are allowed only in tests to keep the suite fast.

Data Protection action-token tests must cover round-trip, tampering, purpose separation,
URL-safe encoding and DI registration. Use an ephemeral provider only inside tests.

Generated OTP tests must cover exact code format, wrong/malformed input, full context
binding, historical HMAC key verification and DI registration.
