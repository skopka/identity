# Infrastructure Test Instructions

Read `../../AGENTS.md` and `../../src/Skopka.Identity.Infrastructure/AGENTS.md` first.

Credential tests must cover verifier format handling, wrong passwords, parameter
upgrades, pepper rotation and malformed/untrusted verifier input. Reduced work factors
are allowed only in tests to keep the suite fast.

Data Protection action-token tests must cover round-trip, tampering, purpose separation,
URL-safe encoding and DI registration. Use an ephemeral provider only inside tests.

Generated OTP tests must cover exact code format, wrong/malformed input, full context
binding, historical HMAC key verification and DI registration.

Rate-limit partition tests must prove deterministic scope-bound HMAC output, absence of
raw identifiers and DI registration with configured policies.

Session adapter tests must cover JWT claims, signature, issuer, audience, expiry,
tamper rejection, opaque refresh-token parsing and DI registration.

Bearer tests must exercise the real ASP.NET authentication service, `Name`/`IsInRole`
mapping, optional online session rejection and composition with application events.
