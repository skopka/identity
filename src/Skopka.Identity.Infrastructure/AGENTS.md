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
  `IPasswordCredentialService<TProfile>`. Do not make the facade package depend on
  Argon2.
