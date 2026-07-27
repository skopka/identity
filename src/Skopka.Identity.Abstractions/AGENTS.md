# Abstractions Module Instructions

Read `../../AGENTS.md` first. This file narrows the rules for
`Skopka.Identity.Abstractions`.

## Purpose

This module is the public contract surface of the library. It contains interfaces,
commands, public models, error DTOs, error codes, handles, metrics contracts and other
small value objects.

## Allowed Responsibilities

- Define stable public contracts such as `IIdentityUserService<TProfile>`,
  `IIdentityUserStore<TProfile>`, `IIdentityNormalizer`, `IUserOperationPolicy`,
  `IProfilePatch<TProfile>` and metrics interfaces.
- Define use-case input records under `Users/Commands`.
- Define store-facing input records such as `NewIdentityUser<TProfile>` when the store
  needs data prepared by Core without depending on service commands.
- Define public domain models such as `IdentityUser<TProfile>`, `IdentityProfile`,
  `UserFlags` and role/handle records.
- Define stable error code constants and serializable error details.
- Define narrow credential contracts such as `IPasswordHasher`,
  `IPasswordPepperProvider`, `IPasswordCredentialService<TProfile>`,
  `IPasswordCredentialStore<TProfile>` and `PasswordVerificationResult`. Keep verifier
  strings opaque to consumers.
- Define authentication contracts such as `IPasswordAuthenticationService<TProfile>`,
  `IIdentityUserLookupStore<TProfile>` and `IPasswordVerificationTimingProtector`.
- Define security stamp contracts such as `ISecurityStampService<TProfile>` and
  `ISecurityStampGenerator`.

## Boundaries

- Do not reference `Core`, EF Core, PostgreSQL, ASP.NET Core, infrastructure adapters or
  concrete persistence packages.
- Do not implement business orchestration here.
- Do not put password hashing, token generation, email sending, SMS sending or database
  provider logic here.
- Do not expose password storage details. Credential data must stay opaque to consumers.

## Contract Rules

- Keep contracts small and durable. Public changes here have the largest compatibility
  cost.
- Commands are service API inputs, not a requirement to introduce CQRS or command
  handlers.
- Store contracts should speak in persistence-oriented inputs and domain outputs, not in
  high-level use-case command records.
- All async public contracts accept `CancellationToken ct`.
- Expected domain failures are represented by `OperationResult` and stable error codes.
