# Skopka.Identity

[![CI](https://github.com/skopka/identity/actions/workflows/ci.yml/badge.svg)](https://github.com/skopka/identity/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/skopka/identity/blob/main/LICENSE)

Skopka.Identity is a transport-neutral identity library for ASP.NET Core. It owns user
lifecycle, password credentials, verification, sessions, roles and persistence while
leaving HTTP endpoints, UI, delivery channels and application authorization to the host.

The project is an alternative set of identity building blocks. It is not API-compatible
with `Microsoft.AspNetCore.Identity`.

> The API is pre-1.0 and currently targets .NET 10. Validate the library against your
> threat model and deployment requirements before using it in production.

## Features

- Generic application profile stored as PostgreSQL `jsonb`.
- Nullable user name, email and phone for external-login-only users.
- Optimistic concurrency through a numeric user version.
- Soft delete, restore and permanent or temporary blocking.
- PBKDF2-HMAC-SHA256 and peppered Argon2id password verifiers.
- Configurable password bounds and application-defined asynchronous validators.
- Password authentication with account/client rate-limiting extension points.
- Email, phone and password-reset action tokens based on ASP.NET Core Data Protection.
- OTP challenge/proof orchestration with HMAC-protected generated codes.
- Short-lived JWT access tokens and rotating opaque refresh sessions.
- Optional online access-token/session validation.
- Role CRUD, direct memberships and role projection into session claims.
- Step-up verification decisions separated from normal application authorization.
- EF Core stores, PostgreSQL mappings and packaged migrations.

External login providers, TOTP, WebAuthn/passkeys and UI/endpoints are not implemented
yet.

## Packages

| Package | Purpose |
| --- | --- |
| `Skopka.Identity.Abstractions` | Public contracts, commands, models and error codes |
| `Skopka.Identity.Core` | Validation and identity orchestration |
| `Skopka.Identity` | Consumer-facing dependency injection and composition |
| `Skopka.Identity.Ef` | Provider-neutral EF Core entities and stores |
| `Skopka.Identity.Ef.PostgreSql` | PostgreSQL mappings, stores and migrations |
| `Skopka.Identity.Infrastructure` | Password hashers, tokens, OTP, rate limiting and JWT |

A typical ASP.NET Core application references:

```shell
dotnet add package Skopka.Identity
dotnet add package Skopka.Identity.Ef.PostgreSql
dotnet add package Skopka.Identity.Infrastructure
```

## Quick Start

Define one profile type for the application:

```csharp
public sealed record AppProfile(
    string DisplayName,
    string? Locale);
```

Register the identity services, PostgreSQL store and one password hasher:

```csharp
using Microsoft.Extensions.DependencyInjection;

var identity = builder.Services
    .AddSkopkaIdentity<AppProfile>()
    .ConfigurePasswordPolicy(options =>
    {
        options.MinimumLength = 15;
        options.MaximumLength = 128;
    })
    .UsePostgreSql(
        builder.Configuration.GetConnectionString("Identity")
        ?? throw new InvalidOperationException(
            "The Identity connection string is missing."))
    .UsePbkdf2PasswordHasher();
```

The default password policy is already `15..128` Unicode code points. The minimum can
be lowered to 8 for applications that enforce multi-factor authentication. Passwords
are never trimmed or normalized, and there are no character-class composition rules.

Apply packaged migrations during deployment. For local development, a host can apply
them explicitly:

```csharp
using Microsoft.EntityFrameworkCore;
using Skopka.Identity.Ef.PostgreSql;

await using var scope = app.Services.CreateAsyncScope();
var identityDb = scope.ServiceProvider.GetRequiredService<
    PostgreSqlIdentityDbContext<AppProfile>>();
await identityDb.Database.MigrateAsync();
```

Do not let every application replica race to run migrations in production. Prefer a
dedicated deployment or migrator step.

Create a user and set a password through the public services:

```csharp
using Skopka.Identity;
using Skopka.Identity.Credentials;
using Skopka.Identity.Users.Commands;

var users = scope.ServiceProvider.GetRequiredService<
    IIdentityUserService<AppProfile>>();
var credentials = scope.ServiceProvider.GetRequiredService<
    IPasswordCredentialService<AppProfile>>();

var created = await users.CreateAsync(
    new CreateUserCommand<AppProfile>(
        "alice",
        "alice@example.com",
        null,
        new AppProfile("Alice", "en")),
    cancellationToken);

if (!created.IsSuccess)
{
    return Results.BadRequest(created.Errors);
}

var password = await credentials.SetPasswordAsync(
    new SetPasswordCommand(
        created.Value.Id,
        created.Value.Version,
        submittedPassword),
    cancellationToken);
```

Commands return `OperationResult` instead of throwing for expected domain failures.
Persist and submit the latest `IdentityUser.Version` for mutations that require
optimistic concurrency.

Authenticate with a user name or email:

```csharp
using Skopka.Identity.Authentication;

var passwords = scope.ServiceProvider.GetRequiredService<
    IPasswordAuthenticationService<AppProfile>>();

var authentication = await passwords.AuthenticateAsync(
    new AuthenticatePasswordCommand(
        PasswordLoginHandle.Email,
        "alice@example.com",
        submittedPassword,
        clientKey),
    cancellationToken);
```

`clientKey` is trusted transport context created by the host, such as a protected IP
partition key. Do not accept it directly from an untrusted request body.

## Argon2id With Pepper

Load pepper keys from a secret manager, not configuration committed to source:

```csharp
using Skopka.Identity.Credentials;

var pepperKey = Convert.FromBase64String(
    builder.Configuration["Identity:PasswordPepper"]
    ?? throw new InvalidOperationException("Password pepper is missing."));

var pepperProvider = new StaticPasswordPepperProvider(
    currentKeyId: "2026-01",
    currentKey: pepperKey);

builder.Services
    .AddSkopkaIdentity<AppProfile>()
    .UsePostgreSql(connectionString)
    .UseArgon2idPepperedPasswordHasher(pepperProvider);
```

Keep old pepper keys available during rotation until every verifier has been upgraded.
The stored verifier contains only the key id and KDF parameters, never the pepper.

## JWT Sessions

JWT sessions are optional. Signing keys must contain at least 32 random bytes and must
be shared by every issuing and validating instance:

```csharp
var signingKey = Convert.FromBase64String(
    builder.Configuration["Identity:JwtSigningKey"]
    ?? throw new InvalidOperationException("JWT signing key is missing."));

builder.Services
    .AddSkopkaIdentity<AppProfile>()
    .UsePostgreSql(connectionString)
    .UseJwtSessions(
        signingKey,
        jwt =>
        {
            jwt.Issuer = "https://identity.example.com";
            jwt.Audience = "example-api";
        })
    .UseJwtBearerAuthentication(options =>
    {
        options.ValidateSessionOnEveryRequest = false;
    });
```

Stateless validation accepts a correctly signed access token until its short expiry.
Set `ValidateSessionOnEveryRequest` to `true` when immediate refresh-session revocation
is worth a database lookup on every request. Role changes appear in newly created or
refreshed access tokens; existing stateless JWTs retain their embedded claims.

## Optional Modules

All optional modules compose through `IdentityBuilder<TProfile>`:

```csharp
identity
    .UseDataProtectionActionTokens()
    .UseHmacOneTimeCodes("otp-2026-01", otpHmacKey)
    .UseHmacRateLimiting(rateLimitPartitionKey)
    .AddRoles()
    .AddStepUpAuthorization<ApplicationStepUpPolicyProvider>();
```

Use separate random keys for password peppering, JWT signing, OTP verification and
rate-limit partition hashing. Persist and share the ASP.NET Core Data Protection key
ring in multi-instance deployments.

## Design and Operations

- [Architecture](https://github.com/skopka/identity/blob/main/docs/architecture.md)
- [Migrating from ASP.NET Core Identity](https://github.com/skopka/identity/blob/main/docs/migration-from-aspnet-core-identity.md)
- [Security model and deployment checklist](https://github.com/skopka/identity/blob/main/docs/security.md)
- [Build, tests and PostgreSQL integration tests](https://github.com/skopka/identity/blob/main/docs/testing.md)
- [Release process](https://github.com/skopka/identity/blob/main/docs/releasing.md)

## License

Skopka.Identity is licensed under the
[Apache License 2.0](https://github.com/skopka/identity/blob/main/LICENSE).
