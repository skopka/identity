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
- `src/Skopka.Identity.Infrastructure` - infrastructure adapters.
- `src/Skopka.Identity` - facade/DI package layer.

Each module has its own local `AGENTS.md`. When editing inside a module, read the root
file first and then the module-local file:

- `src/Skopka.Identity.Abstractions/AGENTS.md`
- `src/Skopka.Identity.Core/AGENTS.md`
- `src/Skopka.Identity.Ef/AGENTS.md`
- `src/Skopka.Identity.Ef.PostgreSql/AGENTS.md`
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
- `IPasswordAuthenticationService<TProfile>` authenticates an explicit username or email
  login without exposing whether the user or credential exists.
- `IIdentityUserLookupStore<TProfile>` provides active-user lookup by normalized login
  handles.
- `ISecurityStampService<TProfile>` rotates and validates session invalidation stamps.
- `ISecurityStampGenerator` creates opaque random stamp values.
- `IIdentityActionTokenIssuer<TProfile>` issues confirmation and password-reset tokens.
- `IIdentityActionTokenProvider` protects and reads purpose-bound token payloads.
- `IIdentityNormalizer` normalizes userName/email/phone before persistence and checks.
- `IUserOperationPolicy` decides whether the current user flags allow mutation.
- `IProfilePatch<TProfile>` applies partial profile changes.
- `IIdentityMetrics` and `IIdentityOpScope` measure service operations.

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
password rehash. Future credential changes such as external login removal must rotate it
as well.

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

Mutation commands use `ExpectedVersion` except `ConfirmEmailCommand` and
`ConfirmPhoneCommand`, which intentionally do not accept `ExpectedVersion`.

## Business Rules

Preserve these rules:

- A user may exist without `UserName`, `Email` and `Phone`. Handles are nullable because
  external login providers are planned. Do not require at least one local handle on
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
- Password hashing contracts live under `Skopka.Identity.Credentials`. Infrastructure
  provides `Pbkdf2PasswordHasher` and `Argon2idPepperedPasswordHasher`. HMAC-SHA256 is
  used as a peppered pre-hash, not as encryption. Pepper keys remain outside persistence
  and are resolved by versioned key id.
- Password authentication uses an explicit `PasswordLoginHandle` to avoid ambiguity
  between usernames and emails. Unknown users, missing credentials and wrong passwords
  return the same invalid-credentials error. Unknown/missing-credential paths must run a
  configured dummy password verification workload.
- Security stamp changes and credential mutations bump `Version` in the same persistence
  operation. Stamp validation rejects missing, deleted and actively blocked users.
- Soft delete rotates the stamp so restoring a user cannot reactivate sessions issued
  before deletion.
- Email confirmation, phone confirmation and password reset are separate action-token
  purposes. Tokens cannot be reused across purposes. Password reset rotates the security
  stamp atomically with the verifier change, making a successfully used reset token
  invalid.
- Action tokens are not OTP authenticators. Keep future TOTP/SMS/email OTP challenge
  state, attempt limits and MFA rules in a separate subsystem.
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
- `user_credentials`
  - opaque password verifier
  - credential update timestamp
- planned later:
  - `user_external_logins`

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
action tokens are implemented. The next security-critical area is authentication attempt
tracking and rate limiting. Keep request/IP-aware throttling out of the password hasher
and low-level EF lookup store.

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
