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
- Define bounded password-policy options and
  `IPasswordValidator<TProfile>` extension contracts. Validator context may expose the
  user and mutation kind, but must not expose verifier/hash implementation details.
- Define authentication contracts such as `IPasswordAuthenticationService<TProfile>`,
  `IIdentityUserLookupService<TProfile>`,
  `IIdentityUserLookupStore<TProfile>`, bounded automatic-login normalization and
  `IPasswordVerificationTimingProtector`.
- Keep the default-compatible `NormalizePhoneLoginIdentifier` contract transport-neutral
  and overrideable; Core and hosts share it instead of duplicating phone-shape policy.
- Define security stamp contracts such as `ISecurityStampService<TProfile>` and
  `ISecurityStampGenerator`.
- Define action-token contracts under `Tokens`, including purposes, protected payload,
  issuer, provider and configurable lifetimes. Action tokens must not depend on ASP.NET
  Core Data Protection at this layer.
- Define Verification contracts for challenge lifecycle, concrete method providers,
  one-time proofs and persistence ports. Keep business intents opaque through
  server-created `Purpose` and `Binding` values.
- Define StepUp contracts for server-created action/resource context, dynamic policy
  requirements and one-time proof-to-decision exchange. Decisions are transport-neutral
  in-memory results, not bearer tokens.
- A successful `StepUpDecision` does not grant domain permission by itself. The
  application remains responsible for its normal role/policy authorization.
- Define transport-neutral rate-limit requests, decisions, options, bucket stores and
  versioned partition-hasher contracts. Version metadata is derivation-agnostic and
  must not depend on HMAC. Do not reference ASP.NET rate-limiter or HTTP types.
- Define transport-neutral session contracts under `Sessions`: access/refresh providers,
  session commands, issued token pairs, refresh persistence models and store ports.
- Define bounded session-claim values and
  `IIdentitySessionClaimsProvider<TProfile>` without depending on
  `System.Security.Claims` or ASP.NET Core.
- Define role CRUD, direct membership and bounded role-query contracts under `Roles`.
  Role store inputs carry normalized names prepared by Core; membership APIs use stable
  role ids and queries never expose `IQueryable`.
- Define atomic registration contracts under `Registration` and external identity
  lifecycle contracts under `ExternalLogins`.
- Define a transport-neutral sign-in-method snapshot query under `SignInMethods`. It may
  expose password presence and trusted external-login keys, but never a password
  verifier.
- Define bounded cursor-based user query contracts under `Users/Queries`; never expose
  EF or `IQueryable`.
- Define WebAuthn contracts under `WebAuthn`: the credential model, the persistence
  port and the ceremony verifier. Public keys are DER SubjectPublicKeyInfo rather than
  COSE, so consumers never parse an authenticator wire format. The verifier is
  synchronous and takes everything it compares against as arguments.
- Define security-event observer contracts under `SecurityEvents`. Events contain no
  credentials, tokens, handles or provider subjects.

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
- Password validators return `OperationResult`, accept cancellation and may perform
  asynchronous application checks. They do not hash or persist passwords.
- Confirmation commands include the target handle and protected token, but intentionally
  omit `ExpectedVersion`. Password reset includes the protected token and new password.
- Verification methods return opaque persisted verifiers and optional delivery codes.
  The abstraction must not require generated OTP, because future TOTP or WebAuthn
  methods may not issue a deliverable code.
- `CreateAndSupersedeAsync` is an atomic store contract. The exact intent tuple is
  `(UserId, Purpose, Binding, Method)` with ordinal string equality. A new challenge
  supersedes all `Pending` and `Verified` rows for that tuple, including expired rows,
  increments their versions and leaves at most one active row under concurrent calls.
  Different tuples must remain independent.
- Step-up commands do not accept a verification purpose. The policy provider owns it,
  preventing transport callers from selecting a weaker or unrelated purpose.
- Step-up `AssuranceLevel` is an application-defined ordinal for policy comparison. It
  does not by itself claim NIST AAL or another external certification level.
- Optional `ClientKey` command fields carry server-created transport context. They are
  not raw client DTO fields and must remain nullable for non-HTTP/background callers.
- Session contracts expose no IdentityModel, JWT bearer middleware or EF types. The
  registry/store contracts model a transport-neutral logical session; refresh-store
  models carry digests and rotation state, never plaintext refresh secrets.
- Protocol/session JWT claims are reserved. Custom providers may emit repeated `role`
  claims but cannot replace issuer, audience, subject, token/session ids or timestamps.
- `IdentityRole.ParentId` is hierarchy metadata only. The public contract does not imply
  inherited membership or authorization.
- External provider subjects remain exact and case-sensitive. Provider protocol tokens
  and claims are outside these contracts.
- `SignInMethodSnapshot.Version` is an optimistic mutation guard for host policy. It is
  not a transactional or reusable authorization decision.
- Session metadata is optional bounded display data. Revoke by id always carries both
  user id and logical session id.
- `IIdentitySecurityEventObserver` is a non-blocking post-commit hook, not a durable
  transactional audit guarantee.
