# Infrastructure Module Instructions

Read `../../AGENTS.md` first. This file narrows the rules for
`Skopka.Identity.Infrastructure`.

## Purpose

This module is for adapters that connect identity domain services to external systems.
It is not the place for core business rules.

## Allowed Responsibilities

- Implement adapters for clocks, token providers, password verifiers, email/SMS delivery,
  metrics bridges or other external services when those abstractions exist.
- Keep credential implementation details hidden behind narrow interfaces.
- Provide infrastructure defaults that can be wired by the facade project.

## Boundaries

- Do not define the primary public domain contracts here; use `Abstractions`.
- Do not implement identity user orchestration here; use `Core`.
- Do not put EF persistence here; use `Skopka.Identity.Ef` or provider modules.
- Do not put ASP.NET Core DI facade methods here unless the facade project delegates to
  infrastructure-specific extensions intentionally.

## Implementation Rules

- Treat external services as unreliable and return typed/expected errors when the
  abstraction supports it.
- Keep dependencies optional and scoped to the specific adapter.
- Avoid making infrastructure packages required for consumers that only need the domain
  core.
- Password verifiers are versioned opaque strings. Never persist plaintext passwords or
  pepper keys.
- `Pbkdf2PasswordHasher` uses PBKDF2-HMAC-SHA256. The peppered provider uses
  HMAC-SHA256 as a pre-hash and Argon2id as the password KDF.
- Pepper key ids must support rotation. Verification with an old available key returns
  `SuccessRehashNeeded`; a missing key returns `Failed`.
- Password hasher DI extensions live in this optional module and extend
  `IdentityBuilder<TProfile>`. Selecting a hasher also registers
  `IPasswordCredentialService<TProfile>`, `IPasswordAuthenticationService<TProfile>` and
  a singleton dummy-verification workload. Do not make the facade package depend on
  Argon2.
- Hashers implement only verifier creation and verification. Password length policy and
  custom validators are enforced by Core before invoking a hasher.
- `DataProtectionIdentityActionTokenProvider` cryptographically separates each token
  purpose and emits URL-safe protected payloads. Malformed, tampered and cross-purpose
  tokens must fail without throwing expected validation exceptions.
- `UseDataProtectionActionTokens<TProfile>()` explicitly enables the default action-token
  subsystem and configures its lifetimes. Production and multi-instance applications
  must persist and share the ASP.NET Core Data Protection key ring; ephemeral keys make
  outstanding tokens invalid after restart or when routed to another instance.
- `HmacOneTimeCodeProvider` issues generated numeric OTP values but persists only a
  versioned HMAC-SHA256 verifier bound to the full challenge context. Compare digests in
  fixed time and reject malformed verifier/code input without throwing.
- Verification-code HMAC keys are separate from password peppers and Data Protection
  keys. Key providers retain historical keys until all challenges issued under them have
  expired.
- `UseHmacOneTimeCodes<TProfile>()` enables generated OTP and configures code length,
  challenge lifetime, proof lifetime and per-challenge failed-attempt limit. Delivery is
  the caller's responsibility. Treat returned delivery codes as secrets and never log
  them.
- `HmacRateLimitPartitionHasher` obscures account, client and intent identifiers before
  persistence. Its versioned keys are distinct deployment secrets, copied on
  registration and cleared on disposal.
- `UseHmacRateLimiting<TProfile>()` explicitly enables the persistent limiter and
  configures password account/client, verification account/client, intent and resend
  policies plus bucket retention/cleanup batch size. Rotation configurations expose the
  current version and overlapping historical `(version, key)` pairs. All instances
  sharing the database must overlap on at least one version during rolling deployment.
- `UseRateLimiting<TProfile>()` accepts a custom non-HMAC
  `IRateLimitPartitionHasher`; its version identifiers follow the same persistence and
  rotation rules.
- `HmacJwtAccessTokenProvider` uses Microsoft IdentityModel and HS256 with explicit
  issuer, audience, lifetime, signature and algorithm validation. Signing keys contain
  at least 256 bits and remain outside persistence.
- `OpaqueRefreshTokenProvider` creates versioned tokens with a 256-bit random secret and
  exposes only a SHA-256 digest for persistence.
- `UseJwtSessions<TProfile>()` explicitly enables Core session orchestration and its
  token providers. The versioned overload signs with the current key id and validates
  against a bounded overlapping key set. A present `kid` resolves strictly; legacy
  tokens without `kid` may try the configured overlap. JWT signing keys must be shared
  by token issuers and validators and retained through access-token expiry plus rollout.
- `UseJwtBearerAuthentication<TProfile>()` configures ASP.NET Core authentication with
  the same HMAC validation parameters, disables inbound claim remapping and maps `name`
  and repeated `role` claims for `ClaimsPrincipal`. It also registers standard
  authorization services.
- Bearer validation is stateless by default. Optional per-request online session
  validation must compose with, not replace, the application's `OnTokenValidated`
  callback.
