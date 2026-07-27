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

`SecurityStamp` is intentionally not part of the current model. It is planned separately.

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

Mutation commands use `ExpectedVersion` except `ConfirmEmailCommand` and
`ConfirmPhoneCommand`, which intentionally do not accept `ExpectedVersion`.

## Business Rules

Preserve these rules:

- A user may exist without `UserName`, `Email` and `Phone`. Handles are nullable because
  external login providers are planned. Do not require at least one local handle on
  create or update unless the user explicitly changes this rule.
- Confirmation operations do not use expected version, but must validate that the
  email/phone from the confirmation command still matches the user's current value after
  normalization. This protects against stale confirmation links/tokens.
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
  - deleted and blocked timestamps
- `user_profiles`
  - display handles
  - `Profile` stored as `jsonb`
- planned later:
  - `user_credentials`
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

Continue from the existing code. The active implementation areas are:

1. Align and finish `IdentityUserService<TProfile>` in `Skopka.Identity.Core`.
   Responsibilities:
   - validation
   - policy checks
   - normalization
   - metrics
   - orchestration
   - calling `IIdentityUserStore<TProfile>`

2. Implement or finish `EfIdentityUserStore<TProfile>` in the EF Core layer.
   Responsibilities:
   - EF Core persistence
   - mapping entities to `IdentityUser<TProfile>`
   - optimistic concurrency handling
   - unique violation mapping
   - timestamp and version updates

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
