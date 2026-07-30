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
- Enforce the mandatory password length baseline and orchestrate registered
  `IPasswordValidator<TProfile>` implementations.
- Implement `IPasswordAuthenticationService<TProfile>` and dummy verification workload.
- Implement exact normalized active-user lookup through
  `IIdentityUserLookupService<TProfile>` for trusted application orchestration.
- Implement `ISecurityStampService<TProfile>` and the default random stamp generator.
- Implement `IIdentityActionTokenIssuer<TProfile>` and validate action-token bindings in
  confirmation/password-reset use cases.
- Implement `IIdentityVerificationService<TProfile>` challenge orchestration and
  one-time proof generation/consumption.
- Implement optional `IIdentityStepUpService<TProfile>` orchestration over Verification:
  resolve current policy, enforce method/intent/age and consume proof before returning
  an authorization decision.
- Implement `IIdentityRateLimiter<TProfile>` hashing/orchestration and apply configured
  policies in password authentication and Verification Begin.
- Implement `IIdentitySessionService<TProfile>` issuance, refresh rotation, online
  access validation, revoke and bounded pruning.
- Provide default projection for user name/email/phone session claims and aggregate
  additional `IIdentitySessionClaimsProvider<TProfile>` implementations.
- Implement optional role CRUD and direct user-role membership orchestration through
  `IdentityRoleService<TProfile>`, including role-name normalization and hierarchy
  validation.
- Project direct role memberships as repeated `role` session claims when roles are
  enabled.
- Implement atomic password/external registration, external-login lifecycle and bounded
  user queries through their dedicated store ports.
- Publish successful security mutations through `IIdentitySecurityEventObserver`
  without exposing secret values.
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
- Exact user lookup may return `identity.user.not_found`; public account-recovery and
  confirmation transports are responsible for suppressing that result.
- Authentication performs one password KDF verification on every credential-denied path.
- Active permanent or temporary blocks reject authentication after password verification;
  expired temporary blocks do not reject authentication.
- Password set/change/removal rotates the security stamp; technical rehash does not.
- New passwords are measured in Unicode code points and checked against the configured
  minimum/maximum without trimming or normalization. Do not add character-class
  composition rules.
- Apply cheap required/maximum checks before any real or dummy password KDF. Do not
  apply the current minimum to existing passwords, because legacy short passwords must
  remain usable long enough to replace them.
- Run custom password validators only after authority is established: after confirming
  no password exists for set, after the current password succeeds for change and after
  the reset token succeeds for reset. Hash only after every validator succeeds.
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
- Step-up policy owns verification requirements; the business use case owns action and
  resource binding. Neither value may be accepted unmodified from an untrusted client.
- Bind Verification to the SHA-256 digest of the length-prefixed action/resource pair,
  not to the raw resource binding alone. This prevents cross-action proof reuse when
  policy purposes are accidentally shared.
- A step-up decision is returned only after successful proof consumption. Do not turn it
  into a reusable bearer credential inside Core.
- Step-up confirms an additional verification requirement; it does not replace role or
  domain authorization checks performed by the application.
- Do not claim cross-module transaction atomicity. The application use case should
  call step-up authorization and mutate its intent in one unit of work when both stores
  can share a transaction.
- Password account rate limiting checks before password verification, records only
  credential failures and resets after a correct password. Preserve one dummy KDF when
  an account partition is denied.
- Client partitions count every request. Never reset a client/IP partition after one
  successful account login.
- Verification client, intent and account partitions are evaluated in that order so
  cooldown-denied resend attempts do not consume account issuance quota.
- Rate-limit maintenance computes the retention cutoff in Core and delegates bounded
  pruning to the store. Do not start background workers in Core.
- Session creation reloads the user and compares the authentication security stamp in
  fixed time. Deleted, actively blocked or stale authentication results cannot create
  sessions.
- Refresh rotation preserves the original absolute expiry. A replayed rotated token
  revokes the complete logical session; a stamp mismatch also revokes that session.
- JWT signing/validation and opaque refresh-token generation are provider
  responsibilities. Core never parses JWT or persists plaintext refresh tokens.
- Online access validation checks the cryptographic payload, active refresh session,
  current user state and security-stamp snapshot. Stateless middleware validation has
  intentionally weaker immediate-revocation semantics.
- Project and validate claims before creating or rotating refresh persistence so a
  failing custom provider cannot consume a usable refresh token.
- Role assignment/removal follows normal user mutation policy and rejects deleted,
  `System` and `Protected` users. Role membership does not bump the user version or
  security stamp.
- Validate role parent references and cycles, but do not expand parent roles into
  inherited JWT claims.
- Canonicalize external provider names but preserve provider subjects exactly. Link and
  unlink rotate the security stamp and enforce expected version.
- Registration validates and hashes before one aggregate store call. Never compose
  public registration from separate user and credential store calls.
- Session metadata is normalized as bounded labels, survives refresh rotation and is
  never used for authorization.
- Security-event callbacks happen only after successful persistence. They must not be
  presented as transactional audit delivery.

## Implementation Style

- Keep service methods direct and readable.
- Use private helpers only when they remove real duplication.
- Return `OperationResult` for expected domain failures.
- Throw exceptions only for programmer errors or truly unexpected infrastructure failures
  that Core cannot translate.
