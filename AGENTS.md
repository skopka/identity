# Agent Instructions

This is the primary context file for AI agents working on `Skopka.Identity`.
Read this first, then inspect only the files relevant to the task.

## Product Goal

`Skopka.Identity` is an open source identity library for ASP.NET Core and a planned
alternative to Microsoft Identity.

The library owns the identity/user domain model, commands, business rules, storage ports
and persistence adapters. Keep business rules separate from ASP.NET transport, UI,
concrete database details and credential implementation details.

Do not redesign the architecture unless the user explicitly asks for that.

## Current Solution Shape

- `src/Skopka.Identity.Abstractions` - public contracts, models, commands, errors,
  metrics interfaces and small DTOs.
- `src/Skopka.Identity.Core` - domain orchestration and default implementations:
  `IdentityUserService<TProfile>`, normalizer, operation policy, errors, noop metrics.
- `src/Skopka.Identity.Ef` - EF Core persistence layer and storage entities. Earlier
  planning notes may call this layer `Skopka.Identity.EfCore`; in this repository the
  actual project name is `Skopka.Identity.Ef`.
- `src/Skopka.Identity.Ef.PostgreSql` - PostgreSQL-specific persistence integration.
- `src/Skopka.Identity.Ef.Sqlite` - SQLite-specific persistence integration.
- `src/Skopka.Identity.Infrastructure` - infrastructure adapters.
- `src/Skopka.Identity` - facade/DI package layer.

Each module has its own local `AGENTS.md`. When editing inside a module, read the root
file first and then the module-local file:

- `src/Skopka.Identity.Abstractions/AGENTS.md`
- `src/Skopka.Identity.Core/AGENTS.md`
- `src/Skopka.Identity.Ef/AGENTS.md`
- `src/Skopka.Identity.Ef.PostgreSql/AGENTS.md`
- `src/Skopka.Identity.Ef.Sqlite/AGENTS.md`
- `src/Skopka.Identity.Infrastructure/AGENTS.md`
- `src/Skopka.Identity/AGENTS.md`

## Main Public Contracts

- `IIdentityUserService<TProfile>` in
  `src/Skopka.Identity.Abstractions/IIdentityUserService.cs` is the main use-case API.
- `IIdentityUserStore<TProfile>` is the storage port used by Core. Core must not depend
  on EF Core, SQL, database indexes or provider-specific transactions.
- `IPasswordCredentialService<TProfile>` orchestrates password credential lifecycle.
- `IPasswordCredentialStore<TProfile>` persists opaque password verifiers and uses the
  user version for optimistic concurrency.
- `IPasswordAuthenticationService<TProfile>` authenticates explicit user-name, email or
  phone handles and supports ambiguity-safe automatic lookup without exposing whether
  the user or credential exists.
- `IIdentityUserLookupService<TProfile>` provides exact normalized active-user email and
  phone lookup for trusted application workflows such as account-message issuance.
- `IIdentityUserLookupStore<TProfile>` provides active-user lookup by normalized login
  handles.
- `ISecurityStampService<TProfile>` rotates and validates session invalidation stamps.
- `ISecurityStampGenerator` creates opaque random stamp values.
- `IIdentityActionTokenIssuer<TProfile>` issues confirmation and password-reset tokens.
- `IIdentityActionTokenProvider` protects and reads purpose-bound token payloads.
- `IIdentityVerificationService<TProfile>` owns begin, verify and one-time proof
  consumption for step-up verification challenges.
- `IVerificationMethodProvider` verifies a concrete method such as a generated OTP.
- `IVerificationChallengeStore<TProfile>` persists challenge state and CAS transitions.
- `IIdentityStepUpService<TProfile>` begins policy-approved verification and exchanges
  a one-time proof for an in-memory authorization decision.
- `IStepUpPolicyProvider<TProfile>` maps a server-created action/resource context to
  allowed verification methods, purpose, assurance level and optional maximum age.
- `IIdentityRateLimiter<TProfile>` applies named fixed-window policies to HMAC-obscured
  account, client and verification-intent partitions.
- `IRateLimitBucketStore<TProfile>` persists rate-limit buckets for multi-instance use.
- `IIdentitySessionService<TProfile>` issues, refreshes, validates and revokes JWT-backed
  identity sessions.
- `IIdentityRefreshSessionStore<TProfile>` persists refresh-token rotation chains.
- `IIdentityAccessTokenProvider` and `IIdentityRefreshTokenProvider` isolate token
  cryptography and wire formats from Core.
- `IIdentitySessionClaimsProvider<TProfile>` projects user/application claims into each
  newly issued access token. Multiple providers and repeated `role` claims are allowed.
- `IWebAuthnCeremonyVerifier` reads a WebAuthn registration response and verifies an
  assertion against a stored public key. It is synchronous and stateless: challenge,
  origins, relying party and key are arguments, not lookups.
- `IWebAuthnCredentialStore<TProfile>` persists public-key credentials and records the
  signature counter of an accepted assertion.
- `IIdentityRoleService<TProfile>` owns role CRUD and direct user-role membership.
- `IIdentityRoleQueryService<TProfile>` provides bounded cursor-based role catalog
  queries without exposing `IQueryable`.
- `IIdentityRoleStore<TProfile>` and `IIdentityUserRoleStore<TProfile>` are the role
  persistence ports used by Core.
- `IIdentityRegistrationService<TProfile>` atomically creates a user with its initial
  password credential or external login.
- `IExternalLoginService<TProfile>` resolves, lists, links and unlinks trusted
  provider/subject identities.
- `IIdentitySignInMethodQueryService<TProfile>` returns password presence, trusted
  external-login keys and the user version for host-owned sign-in policy checks. It
  never exposes a password verifier.
- `IIdentityUserQueryService<TProfile>` provides bounded cursor-based administrative
  queries without exposing `IQueryable`.
- `IIdentitySecurityEventObserver` receives non-blocking notifications after successful
  security mutations. It is not a transactional audit store.
- `IIdentityNormalizer` normalizes userName/email/phone before persistence and checks.
- `IUserOperationPolicy` decides whether the current user flags allow mutation.
- `IProfilePatch<TProfile>` applies partial profile changes.
- `IIdentityMetrics` and `IIdentityOpScope` measure service operations.
- `PasswordPolicyOptions` defines the mandatory bounded baseline, while
  `IPasswordValidator<TProfile>` lets applications add asynchronous checks such as
  password blocklists or breached-password services.

All user-service methods return `OperationResult` / `OperationResult<T>` and accept
`CancellationToken ct`.

## User Model

The public model is:

```csharp
public record IdentityUser<TProfile>(
    Guid Id,
    UserFlags Flags,
    string? UserName,
    string? Email,
    bool EmailConfirmed,
    string? Phone,
    bool PhoneConfirmed,
    TProfile Profile,
    long Version,
    string SecurityStamp,
    DateTimeOffset? DeletedAt,
    DateTimeOffset? BlockedAt,
    DateTimeOffset? BlockedUntil,
    DateTimeOffset CreatedAt,
    DateTimeOffset ModifiedAt);
```

Earlier planning notes may call `UserFlags` by the name `UserType`. In this repository
the current code uses `UserFlags`; treat it as the same domain concept unless the user
explicitly asks for a rename.

`TProfile` is generic and represents one application-specific profile type per
application. Do not bake application profile fields into the core model.

`Version` is a `long` optimistic concurrency token. Do not replace it with timestamps and
do not bypass expected-version checks for mutating commands.

`SecurityStamp` is a random opaque value used to invalidate sessions. It changes on
password set/change/removal, soft delete and explicit rotation, but not on a technical
password rehash. External login link/unlink rotates it as well.

## Commands

The current command set is:

- `CreateUserCommand<TProfile>`
- `ConfirmEmailCommand`
- `ConfirmPhoneCommand`
- `ChangeUserNameCommand`
- `ChangeEmailCommand`
- `ChangePhoneCommand`
- `PatchProfileCommand<TPatch>`
- `BlockUserCommand`
- `UnblockUserCommand`
- `DeleteUserCommand`
- `RestoreUserCommand`
- `SetPasswordCommand`
- `ChangePasswordCommand`
- `RemovePasswordCommand`
- `ResetPasswordCommand`
- `VerifyPasswordCommand`
- `AuthenticatePasswordCommand`
- `RotateSecurityStampCommand`
- `BeginVerificationCommand`
- `VerifyVerificationChallengeCommand`
- `ConsumeVerificationProofCommand`
- `CreateIdentitySessionCommand`
- `RefreshIdentitySessionCommand`
- `RevokeIdentitySessionCommand`
- `RevokeIdentitySessionByIdCommand`
- `RevokeAllIdentitySessionsCommand`
- `ListIdentitySessionsCommand`
- `RegisterPasswordUserCommand<TProfile>`
- `RegisterExternalUserCommand<TProfile>`
- `LinkExternalLoginCommand`
- `UnlinkExternalLoginCommand`

Mutation commands use `ExpectedVersion` except `ConfirmEmailCommand` and
`ConfirmPhoneCommand`, which intentionally do not accept `ExpectedVersion`.

## Business Rules

Preserve these rules:

- A user may exist without `UserName`, `Email` and `Phone`. Handles are nullable for
  external-login-only users. Do not require at least one local handle on
  create or update unless the user explicitly changes this rule.
- Confirmation operations do not use expected version, but must validate that the
  email/phone from the confirmation command still matches the user's current value after
  normalization. They also require a non-expired action token bound to the confirmation
  purpose, user id, normalized handle and current security stamp.
- `ChangeEmail` resets `EmailConfirmed` to `false`.
- `ChangePhone` resets `PhoneConfirmed` to `false`.
- `System` and `Protected` users cannot be mutated through the normal API.
- Soft delete is represented by `DeletedAt`.
- Temporary blocking is represented by `BlockedUntil`; `BlockedAt` belongs to the public
  model and persistence mapping.
- Restore may fail if unique handles were occupied after deletion.
- Credentials are separate from profile data. Storage must hide password implementation
  details such as hash, salt and pepper.
- Password policy defaults to 15 through 128 Unicode code points. Configuration may
  lower the minimum to 8, must support a maximum of at least 64 and cannot raise the
  resource-safety ceiling above 1024.
- Do not normalize passwords or require upper-case, lower-case, digit or symbol
  composition. Application-specific blocklist and breached-password checks belong in
  `IPasswordValidator<TProfile>`.
- Reject empty or oversized password input before any real or dummy password KDF.
  Existing/current passwords are checked only for input bounds so legacy short
  passwords can still authenticate and be changed.
- Password hashing contracts live under `Skopka.Identity.Credentials`. Infrastructure
  provides `Pbkdf2PasswordHasher` and `Argon2idPepperedPasswordHasher`. HMAC-SHA256 is
  used as a peppered pre-hash, not as encryption. Pepper keys remain outside persistence
  and are resolved by versioned key id.
- Password authentication keeps the explicit `UserName`, `Email` and `Phone`
  `PasswordLoginHandle` modes. `Automatic` resolves the bounded normalized candidate set
  through the login-identifier registry and succeeds only when every match belongs to
  one active user. Zero or multiple users, missing credentials and wrong passwords
  return the same invalid-credentials error and preserve the configured dummy password
  verification workload.
- `IIdentityNormalizer.NormalizePhoneLoginIdentifier` is the shared, overrideable phone
  policy for persistence, confirmation, token binding, trusted exact lookup and password
  login. The default accepts a phone-shaped 8-15 ASCII-digit value; invalid non-null
  phone handles fail validation before persistence.
- Password account throttling uses the resolved active user id so explicit, automatic
  and differently formatted aliases share one bucket. Client throttling remains before
  lookup; unknown or ambiguous automatic input uses a deterministic candidate key.
- Security stamp changes and credential mutations bump `Version` in the same persistence
  operation. Stamp validation rejects missing, deleted and actively blocked users.
- Soft delete rotates the stamp so restoring a user cannot reactivate sessions issued
  before deletion.
- Email confirmation, phone confirmation and password reset are separate action-token
  purposes. Tokens cannot be reused across purposes. Password reset rotates the security
  stamp atomically with the verifier change, making a successfully used reset token
  invalid.
- WebAuthn credentials are stored by an identifier that is unique across the table
  rather than per user: an assertion arrives carrying a credential id and nothing else.
  Public keys are kept as DER SubjectPublicKeyInfo, so nothing after registration has to
  know COSE. Attestation statements are read but not verified; judging authenticator
  models needs a trusted metadata set and a policy that belong to an application. A
  signature counter that did not advance is refused, except when it has always been
  zero, which is an authenticator that does not count. Deciding whether the counter may
  move is the verifier's; the store keeps what it is told.
- Action tokens are not OTP authenticators. Keep future TOTP/SMS/email OTP challenge
  state, attempt limits and MFA rules in the separate Verification subsystem.
- Verification owns challenge expiry, failed-attempt limits, purpose/binding/stamp
  checks and the `Pending -> Verified -> Consumed` state machine. Issuing a new
  challenge atomically moves every `Pending` or `Verified` challenge with the exact
  `(user, purpose, binding, method)` intent to `Superseded`, regardless of expiry;
  different intents remain independent. Step-up policy decides
  which verification is required and exchanges the proof for a decision. The business
  feature creates the server-side action/resource binding and executes the action.
- Step-up actions and bindings are server-created values, not raw client DTO fields.
  Policy supplies the verification purpose; clients cannot choose it.
- Step-up hashes the length-prefixed action/resource pair into the Verification binding.
  This prevents proof transfer between actions even if a policy provider accidentally
  reuses the same purpose.
- A successful step-up decision is an in-memory result, not a bearer token. The service
  re-evaluates current policy, checks method/binding/verification age and consumes the
  proof before returning the decision.
- A step-up decision means only that the additional verification requirement was
  satisfied. It does not replace role checks or the application's domain authorization.
- When proof consumption and the protected mutation use stores that can share a
  transaction, the application should wrap both calls in that transaction. The library
  does not claim cross-store atomicity.
- Generated OTP values are never persisted. Infrastructure stores a versioned
  HMAC-SHA256 verifier bound to challenge id, user id, purpose and binding. HMAC keys
  stay outside the database and support key-id rotation.
- A verification proof is a high-entropy one-time secret. Its SHA-256 digest is stored
  with the challenge and consumption uses optimistic concurrency. Security-stamp
  changes invalidate pending challenges and verified proofs.
- Per-challenge `MaxAttempts` does not replace account/IP rate limiting or resend
  cooldown. Persistent rate limiting adds account/client policies and a per-intent
  resend cooldown.
- Password account buckets count only invalid credentials and reset after a correct
  password. Password client buckets count every request and are not reset by a
  successful login.
- Verification start uses three partitions: client request volume, account-wide issued
  challenges and purpose/binding-specific cooldown/limit. A cooldown-denied resend does
  not consume the account issuance quota.
- `ClientKey` is optional transport context, normally derived from a normalized IP or
  trusted gateway/device signal. Transport code must create it server-side and must not
  trust a value supplied by the request body.
- Rate-limit partition derivations expose a current version plus bounded historical
  versions. The HMAC adapter keeps all keys outside the database. During rotation, every
  successful hit is written to every configured version so old and new replicas share
  active counters; remove an old version only after the longest active policy window.
- Hosts must schedule `IIdentityRateLimiter<TProfile>.PruneAsync()` periodically.
  `BucketRetention` must cover every active policy window; cleanup runs in bounded
  batches and no hidden background service is started by the library.
- Map `identity.rate_limit.exceeded` to HTTP 429 and use `RateLimitDetails.RetryAfter`
  for the `Retry-After` response. Core remains transport-neutral.
- Session creation requires the current security stamp returned by the preceding
  authentication result. Core reloads the user and rejects stale, deleted or actively
  blocked authentication state before persisting a session.
- JWT access tokens are short-lived and contain user id, logical session id, token id,
  timestamps and format version. Do not expose the raw security stamp as a JWT claim.
- The default session claims provider projects available user name, email/confirmation
  and phone/confirmation values. Optional roles add direct memberships through
  `AddRoles()`; applications add other domain claims through
  `AddSessionClaimsProvider<TProvider>()`.
- Claim providers cannot override JWT protocol/session claims such as `iss`, `aud`,
  `sub`, `jti`, `sid`, `iat`, `nbf`, `exp` or `skp_ver`. Claims are count/size bounded
  and projected before refresh persistence changes.
- Refresh tokens are opaque 256-bit random secrets. Persistence stores only their
  SHA-256 digest and the non-secret token id needed for lookup.
- Refresh rotation is strict and one-time. Reuse of a rotated token revokes every token
  in the logical session. Rotation preserves an absolute session expiry rather than
  extending the session indefinitely.
- Cryptographic JWT validation is stateless until access-token expiry.
  `ValidateAccessTokenAsync` adds an online database/stamp check when immediate session
  revoke, password-change or user-block enforcement is required.
- `UseJwtBearerAuthentication<TProfile>()` configures ASP.NET Core JWT bearer validation
  against the same current/overlapping HMAC key set, issuer and audience used by
  `UseJwtSessions<TProfile>()`.
  It also registers standard authorization services. Stateless validation is the
  default. `ValidateSessionOnEveryRequest` composes an online session check after the
  application's `OnTokenValidated` callback.
- Versioned JWT signing emits the current key id as `kid` and resolves a present id
  strictly. Legacy tokens without `kid` may try only the bounded configured overlap.
  Retire an old key after the access-token lifetime, clock skew and rollout interval.
- Hosts still call `UseAuthentication()` and `UseAuthorization()` in their ASP.NET Core
  middleware pipeline. Claims embedded in a stateless token remain unchanged until a
  new token is issued. Role changes appear on the next create/refresh; applications
  needing immediate effect should revoke the user's sessions and enable online session
  validation, or evaluate membership from storage in an authorization policy.
- Hosts must schedule either `IIdentitySessionService<TProfile>.PruneAsync()` or
  `IIdentitySessionRegistry<TProfile>.PruneAsync()` in bounded batches. Logical sessions
  and their rotated token rows remain until expiry plus retention so replay can be detected.
- Session metadata is bounded host-created display data, not a security signal. List only
  active logical refresh chains and scope revoke-by-id by both user and session id.
- External provider names are trimmed and canonicalized to uppercase. Provider subjects
  are case-sensitive and preserved exactly. Core accepts only identities already
  validated by the host's OAuth/OIDC adapter.
- External login link/unlink uses normal mutation policy, expected user version and
  security-stamp rotation. The base domain permits removal of the final sign-in method;
  self-service host policy may be stricter. Such hosts read a sign-in-method snapshot
  and pass its version unchanged to the mutation. A concurrency conflict requires a
  fresh policy/step-up workflow, not an automatic retry of an already authorized action.
- Password and external registration must use `IIdentityRegistrationStore<TProfile>` so
  the user and initial sign-in method commit atomically.
- User and role queries are bounded to 100 rows and use stable `(CreatedAt, Id)` cursor
  ordering.
  Query services are not endpoint authorization.
- Exact account workflows use `IIdentityUserLookupService<TProfile>` rather than
  administrative contains-search. Its not-found result must be suppressed by public
  recovery/confirmation transports when user enumeration is a concern.
- Security-event observers run after successful persistence and must enqueue quickly
  without throwing. Durable compliance audit belongs in a host transactional outbox.
- Action tokens are stateless and do not require EF entities. The default Infrastructure
  provider uses ASP.NET Core Data Protection. Multi-instance deployments must persist
  and share their Data Protection key ring.
- Token issuance returns the token to the caller; email/SMS delivery and
  user-enumeration-safe HTTP responses belong to transport/infrastructure integration,
  not Core.
- Store operations receive `now` from the service; do not recompute operation time in
  lower-level domain orchestration.
- Expected domain failures should return `OperationResult` errors, not throw exceptions.
- Successful operations should mark metrics with `op.Success()`, failures with
  `op.Failure(errorCode)`.

## Persistence Model

EF Core storage is split:

- `auth_users`
  - normalized handles
  - confirmed flags
  - version
  - security stamp
  - deleted and blocked timestamps
- `user_profiles`
  - display handles
  - `Profile` stored as `jsonb`
- `identity_login_identifiers`
  - distinct normalized login keys for each user
  - active-state marker synchronized with soft delete and restore
  - one active owner per normalized key across handle types
- `user_credentials`
  - opaque password verifier
  - credential update timestamp
- `verification_challenges`
  - purpose and server-created intent binding
  - opaque method verifier and security-stamp snapshot
  - failed-attempt count and challenge state
  - one-time proof digest and expiry
- `identity_rate_limit_buckets`
  - versioned, obscured partition key and named scope
  - fixed-window hit count and last-hit timestamp
  - optimistic concurrency version
- `identity_sessions`
  - logical session id, user and security-stamp snapshot
  - absolute expiry, revoke timestamp and optimistic concurrency version
  - optional client/device display labels
- `identity_refresh_sessions`
  - per-rotation token id and parent logical session id
  - refresh-token digest, rotation timestamp and replacement link
  - optimistic concurrency version
- `identity_roles`
  - display and unique normalized names
  - optional parent metadata, version and audit timestamps
- `identity_user_roles`
  - direct user-role memberships and assignment timestamp
- `user_external_logins`
  - canonical provider and exact subject composite key
  - user reference and creation timestamp

PostgreSQL requirements:

- `Version` is configured as `IsConcurrencyToken()`.
- Use filtered unique indexes for non-deleted users and non-null values:
  - `normalized_user_name`
  - `normalized_email`
  - `normalized_phone`
- Map unique constraint violations to duplicate-handle domain errors.
- Map EF concurrency conflicts to the identity concurrency error.
- Bump timestamps/version consistently in persistence operations.

PostgreSQL migrations are packaged in `Skopka.Identity.Ef.PostgreSql`. Because the
runtime context is generic, migration discovery uses
`PostgreSqlIdentityMigrationsAssembly` and a design-time profile factory. Preserve the
runtime tests that verify migrations are visible for an arbitrary `TProfile` and that
there are no pending model changes.

## Current Implementation Direction

Continue from the existing code. User lifecycle, password credentials, password
authentication by username/email, security stamp rotation/validation and stateless
action tokens are implemented. Verification challenges and generated HMAC OTP are
implemented as a separate subsystem. Persistent account/client rate limiting,
challenge-start throttling and resend cooldown are implemented. JWT access tokens and
persistent refresh sessions now support strict rotation, replay detection, online
validation and revoke. ASP.NET Core JWT bearer integration and extensible claims
projection are implemented. Optional role CRUD, bounded role queries, direct membership
persistence and JWT role projection are implemented. Optional policy-driven step-up
decisions exchange
one-time verification proofs without issuing another bearer token. External login
lifecycle, atomic registration, active-session management, bounded administrative user
and role queries and security-event observer hooks are implemented. OAuth/OIDC protocol
clients,
HTTP endpoints and UI belong to a host such as `Skopka.Hello`. Keep transport token
issuance out of password/OTP cryptographic providers and EF stores.

`IdentityRole.ParentId` is validated against missing parents and cycles, but does not
imply inherited membership or inherited JWT claims.

Do not move EF responsibilities into Core. Do not move domain policy decisions into EF
unless the store is only translating database outcomes into domain errors.

## Errors

Use stable identity error codes from:

- `src/Skopka.Identity.Abstractions/Errors/IdentityErrorCodes.cs`
- `src/Skopka.Identity.Core/Users/IdentityErrors.cs`

When adding a new expected domain failure, add a stable string code and a factory method
where appropriate.

## Architectural Boundaries

- `Abstractions` must not depend on `Core`, EF, PostgreSQL or infrastructure.
- `Core` may depend on `Abstractions`, but not on EF Core or a concrete database.
- EF projects implement persistence details and must honor the store contract.
- The facade/DI project wires the library for consumers; do not put domain rules there.
- Do not mix public `IdentityUser<TProfile>` with EF entities.
- Do not add ASP.NET controllers, HTTP DTOs, UI models or auth middleware to Core.

## Coding Style

- C# with nullable reference types and implicit usings.
- Current target framework is `net10.0`.
- Root namespace is `Skopka.Identity`.
- Package versions are managed centrally in `Directory.Packages.props`. Do not add
  `Version` metadata to project-level `PackageReference` items. Keep Microsoft ASP.NET
  Core, EF Core and Extensions packages on the same servicing version.
- Prefer records for commands/DTOs and sealed classes for concrete implementations.
- Keep public contracts small and stable.
- Add abstractions only when required by a concrete scenario.
- Comments should explain non-obvious domain decisions, not restate code.

## Verification

Default verification:

```powershell
dotnet build Skopka.Identity.slnx
```

If tests are added or a test project appears, also run the relevant `dotnet test`.

`Skopka.Identity.Ef.PostgreSql.Tests` contains an explicit Testcontainers integration
test. Running the complete suite requires Docker and access to the pinned
`postgres:17-alpine` image; the test never falls back to a developer-local database.

Release documentation lives in `README.md`, `SECURITY.md`, `CONTRIBUTING.md` and
`docs/`. Keep setup examples, package metadata, CI commands and documented security
semantics aligned with the public API.

Package metadata is centralized in `Directory.Build.props`; module-specific descriptions
remain in source project files. CI must build, run the real PostgreSQL test, audit NuGet
dependencies and pack all seven source packages without publishing them. Tag pushes
matching `v*` publish all seven packages through `.github/workflows/release.yml`; keep the
tag-derived version, package count validation, NuGet.org publication and GitHub Release
attachments aligned. Release setup and operator steps live in `docs/releasing.md`.
