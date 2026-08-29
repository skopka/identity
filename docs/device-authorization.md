# Device authorization requests

`Skopka.Identity` provides a transport-neutral, persistent request state
machine for sign-in approval on an already authenticated device. It is
inspired by RFC 8628, but it is not an OAuth Device Authorization Grant and
does not expose a token endpoint. The HTTP and Razor flows belong to a host
such as `Skopka.Hello`.

## Registration

Register the feature on the existing identity builder after the normal
session and EF provider composition:

```csharp
var identity = services
    .AddSkopkaIdentity<AppProfile>()
    .UsePostgreSql(connectionString)
    .UseJwtSessions(currentKeyVersion, signingKeys);

identity.AddDeviceAuthorization<AppProfile>(options =>
{
    options.RequestLifetime = TimeSpan.FromMinutes(2);
    options.RequiredStepUpMethod = "totp";
    options.StepUpMaximumAge = TimeSpan.FromMinutes(2);
    options.RetentionAfterExpiration = TimeSpan.FromDays(1);
    options.CleanupBatchSize = 500;
});
```

`UsePostgreSql` and `UseSqlite` register the EF request store. The application
must also register an `IIdentitySessionService<TProfile>` and the step-up
infrastructure used by its transport.

Resolve `IIdentityDeviceAuthorizationService<TProfile>` for `CreateAsync`,
`GetStatusAsync`, `GetApprovalDetailsAsync`, `ApproveAsync`, `DenyAsync`,
`ConsumeAsync` and bounded `PruneAsync` operations. Expected failures are
returned as `OperationResult` values.

## State and consumption safety

The durable states are `Pending`, `Approved`, `Denied`, `Consuming`,
`Consumed` and `Expired`. `Consuming` is an internal reservation visible in
the public state enum so storage adapters can implement the same safety rule:

```text
Pending -> Approved -> Consuming -> Consumed
       \-> Denied       \-> Approved only after a failed session is revoked
Pending/Approved -> Expired
```

Every transition checks the expected numeric version and required source
state. Exactly one consumer can atomically reserve an approved request. Only
that consumer calls the existing `IIdentitySessionService.CreateAsync`, so
the new device receives its own logical and refresh session.

If session creation fails without issuing a session, the reservation returns
to `Approved` while the request is still valid. If final persistence fails
after a session was issued, Identity first revokes that session. It releases
the reservation only when revocation succeeds. If completion and revocation
both fail, the row remains `Consuming`: the request fails closed and cannot
issue a duplicate session. The user must start a new request; retained rows
are removed later by `PruneAsync`.

## Stored data and security

The request stores a random public device code, SHA-256 hash of the separate
browser verifier, short visual user code, state/version timestamps, approver
user id and security-stamp snapshot, target-session metadata, optional client
id/local return URL, and display-only IP/User-Agent/device description. The
raw verifier is returned only from `CreateAsync` and is never persisted.

`ConsumeAsync` uses a fixed-time verifier-hash comparison and revalidates the
approved user's existence, deletion/block state and security stamp before it
reserves consumption. `ApproveAsync` accepts only a fresh `StepUpDecision`
whose user, action, device-code binding and configured method all match.
Transport code must authenticate the approving user, create that exact
step-up decision, and never treat the visual user code, IP or User-Agent as an
authentication factor.

Security observer events are emitted for creation, approval, denial, lazy
expiry and successful consumption. Secrets, verifiers and TOTP responses must
not be added to logs or audit payloads.

Rate limiting uses the configured persistent `IIdentityRateLimiter` when one
is registered. Client keys must come from trusted request context, never from
request DTOs.

## Persistence and migration

Provider migrations add `device_authorization_requests` with a unique device
code and a `(state, expires_at)` index:

- PostgreSQL: `20260829101248_AddDeviceAuthorization`
- SQLite: `20260829101258_AddDeviceAuthorization`

These migrations follow the provider's `AddTotpFactors` migration. Apply all
pending Skopka.Identity migrations in timestamp order; there is no Hello-owned
schema migration for this feature.

Apply the matching provider migration before any application instance enables
the feature. Run migrations in a dedicated deployment/migrator step rather
than concurrently from every replica.

Call `IIdentityDeviceAuthorizationService<TProfile>.PruneAsync` periodically.
It removes at most `CleanupBatchSize` rows whose expiry is older than
`RetentionAfterExpiration`; repeat while a full batch is returned when a
large backlog is possible.
