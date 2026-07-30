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
- Atomic password and external-login registration workflows.
- External login resolve, list, link and unlink lifecycle.
- Optimistic concurrency through a numeric user version.
- Soft delete, restore and permanent or temporary blocking.
- PBKDF2-HMAC-SHA256 and peppered Argon2id password verifiers.
- Configurable password bounds and application-defined asynchronous validators.
- Password authentication with account/client rate-limiting extension points.
- Email, phone and password-reset action tokens based on ASP.NET Core Data Protection.
- OTP challenge/proof orchestration with HMAC-protected generated codes.
- Short-lived JWT access tokens and rotating opaque refresh sessions.
- Active-session listing, device labels and user-scoped session revocation.
- Optional online access-token/session validation.
- Role CRUD, direct memberships and role projection into session claims.
- Bounded cursor-based user queries for administrative interfaces.
- Structured security-event observer hooks for host-side audit pipelines.
- Step-up verification decisions separated from normal application authorization.
- EF Core stores, PostgreSQL mappings and packaged migrations.

OAuth/OIDC protocol clients, TOTP, WebAuthn/passkeys and UI/endpoints are not
implemented here. A host validates the provider response and passes only the trusted
provider/subject pair to the identity services.

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

Register a password user atomically through the public registration service:

```csharp
using Skopka.Identity.Registration;
using Skopka.Identity.Users.Commands;

var registration = scope.ServiceProvider.GetRequiredService<
    IIdentityRegistrationService<AppProfile>>();

var created = await registration.RegisterPasswordAsync(
    new RegisterPasswordUserCommand<AppProfile>(
        new CreateUserCommand<AppProfile>(
            "alice",
            "alice@example.com",
            null,
            new AppProfile("Alice", "en")),
        submittedPassword),
    cancellationToken);

if (!created.IsSuccess)
{
    return Results.BadRequest(created.Errors);
}
```

`RegisterPasswordAsync` persists the user and password verifier in one EF
`SaveChangesAsync`. Use `IIdentityUserService<TProfile>.CreateAsync` only when creating
a user without a credential is intentional.

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

After successful authentication, create a session from the returned user and its current
security stamp:

```csharp
using Skopka.Identity.Sessions;

var sessions = scope.ServiceProvider.GetRequiredService<
    IIdentitySessionService<AppProfile>>();

var issued = await sessions.CreateAsync(
    new CreateIdentitySessionCommand(
        authentication.Value.Id,
        authentication.Value.SecurityStamp,
        new IdentitySessionMetadata("web", "Alice's laptop")),
    cancellationToken);
```

The host decides how to return the access token and protect the refresh token. For a
browser, prefer a `Secure`, `HttpOnly`, `SameSite` cookie and add CSRF protection to
state-changing endpoints.

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

Account UIs can call `ListAsync` and `RevokeByIdAsync`. Revocation is scoped by both
user id and session id, so knowing another user's session id is not sufficient.

## External Login Boundary

The host owns OAuth/OIDC redirects, state, nonce, PKCE and provider token validation.
After validation, pass the provider name and stable provider subject:

```csharp
using Skopka.Identity.ExternalLogins;

var externalLogins = scope.ServiceProvider.GetRequiredService<
    IExternalLoginService<AppProfile>>();

var resolved = await externalLogins.ResolveAsync(
    new ExternalLoginKey("github", validatedProviderSubject),
    cancellationToken);
```

Provider names are canonicalized; subjects are case-sensitive and preserved exactly.
Never use an unverified client-supplied subject, email or access token as the login key.
Use `IIdentityRegistrationService<TProfile>.RegisterExternalAsync` for a new account and
`LinkAsync` only for an authenticated user after the host's required step-up check.

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
- [Building API and UI hosts on Skopka.Identity](https://github.com/skopka/identity/blob/main/docs/building-web-hosts.md)
- [Migrating from ASP.NET Core Identity](https://github.com/skopka/identity/blob/main/docs/migration-from-aspnet-core-identity.md)
- [Security model and deployment checklist](https://github.com/skopka/identity/blob/main/docs/security.md)
- [Build, tests and PostgreSQL integration tests](https://github.com/skopka/identity/blob/main/docs/testing.md)
- [Release process](https://github.com/skopka/identity/blob/main/docs/releasing.md)

## License

Skopka.Identity is licensed under the
[Apache License 2.0](https://github.com/skopka/identity/blob/main/LICENSE).
