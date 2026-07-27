# Core Module Instructions

Read `../../AGENTS.md` first. This file narrows the rules for
`Skopka.Identity.Core`.

## Purpose

This module implements domain orchestration for identity users, password credentials,
password authentication and security stamps. It coordinates validation, normalization,
action-token issuance/validation, policy checks, metrics and calls to storage ports.

## Allowed Responsibilities

- Implement `IIdentityUserService<TProfile>`.
- Implement `IPasswordCredentialService<TProfile>`.
- Implement `IPasswordAuthenticationService<TProfile>` and dummy verification workload.
- Implement `ISecurityStampService<TProfile>` and the default random stamp generator.
- Implement `IIdentityActionTokenIssuer<TProfile>` and validate action-token bindings in
  confirmation/password-reset use cases.
- Implement `IIdentityVerificationService<TProfile>` challenge orchestration and
  one-time proof generation/consumption.
- Implement `IIdentityRateLimiter<TProfile>` hashing/orchestration and apply configured
  policies in password authentication and Verification Begin.
- Provide default domain services such as `DefaultIdentityNormalizer`,
  `DefaultUserOperationPolicy` and default/noop metrics implementations.
- Create domain errors through `IdentityErrors`.
- Enforce business rules that do not require database/provider-specific knowledge.

## Boundaries

- Do not reference EF Core, Npgsql, SQL, ASP.NET Core controllers, HTTP DTOs or concrete
  infrastructure.
- Do not implement persistence, migrations, indexes or provider-specific duplicate
  detection here.
- Do not move domain rules into the facade/DI project.
- Do not introduce MediatR/CQRS handlers unless the user explicitly asks for that
  architecture.

## Business Rules To Preserve

- Users may exist without local handles. `UserName`, `Email` and `Phone` are nullable to
  support future external-login-only users.
- `ConfirmEmail` and `ConfirmPhone` do not accept expected version, but must verify that
  the command value still matches the current user value after normalization.
- Confirmation tokens are bound to purpose, user id, normalized current handle, current
  security stamp and expiry.
- `ChangeEmail` resets `EmailConfirmed` to `false`.
- `ChangePhone` resets `PhoneConfirmed` to `false`.
- `System` and `Protected` users cannot be mutated through normal API policy.
- Mutating commands with `ExpectedVersion` must check optimistic concurrency.
- Store calls receive the `now` value computed by the service.
- Metrics must mark success and failure consistently.
- Unknown users, users without password credentials and wrong passwords return the same
  invalid-credentials error.
- Authentication performs one password KDF verification on every credential-denied path.
- Active permanent or temporary blocks reject authentication after password verification;
  expired temporary blocks do not reject authentication.
- Password set/change/removal rotates the security stamp; technical rehash does not.
- Soft delete rotates the security stamp; restore preserves the post-delete stamp.
- Stamp validation rejects deleted and actively blocked users.
- Password reset does not require the old password or expected version. It validates a
  password-reset token, then atomically replaces the verifier and rotates the security
  stamp. The stamp change invalidates the successfully used reset token.
- Do not treat action tokens as OTP/MFA authenticators or add delivery concerns to Core.
- Verification binds every challenge to user, purpose, intent binding and current
  security stamp. It enforces expiry and failed-attempt limits independently of the
  selected method provider.
- Core stores only a SHA-256 digest of the high-entropy verification proof. Business
  authorization and execution remain outside Verification.
- Do not claim cross-module transaction atomicity. The application use case should
  consume the proof and mutate its intent in one unit of work when both stores can share
  a transaction.
- Password account rate limiting checks before password verification, records only
  credential failures and resets after a correct password. Preserve one dummy KDF when
  an account partition is denied.
- Client partitions count every request. Never reset a client/IP partition after one
  successful account login.
- Verification client, intent and account partitions are evaluated in that order so
  cooldown-denied resend attempts do not consume account issuance quota.
- Rate-limit maintenance computes the retention cutoff in Core and delegates bounded
  pruning to the store. Do not start background workers in Core.

## Implementation Style

- Keep service methods direct and readable.
- Use private helpers only when they remove real duplication.
- Return `OperationResult` for expected domain failures.
- Throw exceptions only for programmer errors or truly unexpected infrastructure failures
  that Core cannot translate.
