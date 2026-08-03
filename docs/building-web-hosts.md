# Building a Web Host on Skopka.Identity

This guide is for projects such as `Skopka.Hello` that add HTTP APIs, OAuth/OIDC
protocol endpoints, browser sessions, account pages, administration and UI on top of
Skopka.Identity.

Skopka.Identity is the domain and persistence foundation. The host remains responsible
for transport security, endpoint authorization, provider protocol validation, cookies,
CSRF protection, delivery channels and user-facing policy.

## Ownership

| Skopka.Identity owns | The web host owns |
| --- | --- |
| User, credential, external-login, role and session state | HTTP endpoints and DTOs |
| Normalization, optimistic concurrency and mutation policy | OAuth/OIDC redirects, state, nonce and PKCE |
| Password hashing and opaque refresh-session persistence | Cookies, CSRF and browser storage |
| Action tokens, verification proofs and step-up decisions | Email/SMS delivery and templates |
| PostgreSQL mappings and packaged migrations | Endpoint and application authorization |
| Stable errors, metrics and security-event hooks | Error-to-HTTP mapping and anti-enumeration responses |
| Bounded user queries | Admin UI policy and profile-specific search |

Do not put ASP.NET types into a `TProfile`, store provider access tokens as external
login subjects, or expose EF entities from host APIs.

## Setup

Reference the facade, PostgreSQL and infrastructure packages:

```shell
dotnet add package Skopka.Identity
dotnet add package Skopka.Identity.Ef.PostgreSql
dotnet add package Skopka.Identity.Infrastructure
```

Define one profile type for the whole host and compose the required modules:

```csharp
public sealed record HelloProfile(
    string DisplayName,
    string? Locale);

var identity = builder.Services
    .AddSkopkaIdentity<HelloProfile>()
    .ConfigurePasswordPolicy(options =>
    {
        options.MinimumLength = 15;
        options.MaximumLength = 128;
    })
    .UsePostgreSql(connectionString)
    .UsePbkdf2PasswordHasher()
    .UseDataProtectionActionTokens()
    .AddRoles();

identity.UseJwtSessions(
    jwtSigningKey,
    options =>
    {
        options.Issuer = "https://hello.example.com";
        options.Audience = "hello-api";
    });
```

Apply the migrations from `Skopka.Identity.Ef.PostgreSql` in a deployment step. Do not
run migrations independently on every production replica.

## Password Registration

Use the aggregate registration service when a user and password must either both exist
or both fail:

```csharp
var registration = services.GetRequiredService<
    IIdentityRegistrationService<HelloProfile>>();

var result = await registration.RegisterPasswordAsync(
    new RegisterPasswordUserCommand<HelloProfile>(
        new CreateUserCommand<HelloProfile>(
            request.UserName,
            request.Email,
            phone: null,
            new HelloProfile(request.DisplayName, request.Locale)),
        request.Password),
    ct);
```

This operation hashes only after validation and persists `auth_users`, `user_profiles`
and `user_credentials` in one EF save. Do not reproduce it as `CreateAsync` followed by
`SetPasswordAsync`; that sequence can leave a credential-less account after a partial
failure.

The base library permits users with no local handles or sign-in methods. If a public
registration endpoint requires an email, acceptance of terms or an invitation, enforce
that host policy before calling the service.

## Password Login and Session Issuance

Authenticate first, then bind the session to the returned security stamp:

```csharp
var authentication = await passwords.AuthenticateAsync(
    new AuthenticatePasswordCommand(
        PasswordLoginHandle.Automatic,
        request.Email,
        request.Password,
        trustedClientKey),
    ct);

if (!authentication.IsSuccess)
{
    return InvalidLoginResponse();
}

var issued = await sessions.CreateAsync(
    new CreateIdentitySessionCommand(
        authentication.Value.Id,
        authentication.Value.SecurityStamp,
        new IdentitySessionMetadata(
            ClientName: "hello-web",
            DeviceName: BuildDeviceLabelFromTrustedRequestContext())),
    ct);
```

`ClientName` and `DeviceName` are display labels, not security decisions. Derive them in
the host, keep them free of raw IP addresses and do not trust them for authorization.

For phone DTO validation, use the configured
`IIdentityNormalizer.NormalizePhoneLoginIdentifier` result as the Identity policy
decision. The default accepts 8-15 ASCII digits with common separators; do not maintain
a separate transport-only interpretation that can diverge from stored/login keys.

If the host uses a custom `IIdentityUserLookupStore<TProfile>`, implement both
`FindActiveByNormalizedPhoneAsync` and
`FindActiveByNormalizedLoginIdentifiersAsync`. The compatibility defaults return no
match; the adapter is responsible for bounded one-query resolution and global active
alias uniqueness.

For browser login, keep refresh tokens in `Secure`, `HttpOnly` cookies. Choose an
appropriate `SameSite` mode and enforce CSRF protection on refresh, logout, linking and
all other state-changing endpoints. Do not expose refresh tokens to CSS or client-side
JavaScript unless the application threat model explicitly accepts that risk.

## External Provider Login

The OAuth/OIDC adapter must validate the provider response before calling Identity:

1. Generate and validate `state`; use nonce and PKCE where the protocol requires them.
2. Exchange and validate the provider token through the provider's supported client.
3. Read the stable provider subject from the validated result.
4. Call `ResolveAsync` with a host-configured provider name and that subject.
5. If no link exists, apply the host's account creation/linking policy.

```csharp
var key = new ExternalLoginKey(
    providerRegistration.IdentityKey,
    validatedPrincipal.Subject);

var resolved = await externalLogins.ResolveAsync(key, ct);
if (resolved.IsSuccess)
{
    return await IssueSessionAsync(resolved.Value, ct);
}
```

Provider names are trimmed and canonicalized to uppercase. Subjects are case-sensitive,
are not normalized and must be the provider's stable identifier. An email address is not
a substitute unless the provider explicitly defines it as the immutable subject.

For a new external-only account, use the atomic operation:

```csharp
var registered = await registration.RegisterExternalAsync(
    new RegisterExternalUserCommand<HelloProfile>(
        new CreateUserCommand<HelloProfile>(
            UserName: null,
            Email: validatedEmail,
            Phone: null,
            Profile: new HelloProfile(displayName, locale)),
        key),
    ct);
```

Do not automatically link an external identity to an existing account merely because
emails match. Linking should require an authenticated current account, the expected
user version and the host's step-up policy:

```csharp
var linked = await externalLogins.LinkAsync(
    new LinkExternalLoginCommand(
        currentUser.Id,
        currentUser.Version,
        key),
    ct);
```

Link and unlink rotate the security stamp and bump the user version. The base domain
allows unlinking the final sign-in method. A stricter self-service host can enforce its
policy without reading credential storage directly:

```csharp
var signInMethods = services.GetRequiredService<
    IIdentitySignInMethodQueryService<HelloProfile>>();
var snapshotResult = await signInMethods.GetAsync(currentUser.Id, ct);
if (!snapshotResult.IsSuccess)
{
    return MapIdentityError(snapshotResult);
}

var snapshot = snapshotResult.Value;
var target = snapshot.ExternalLogins.SingleOrDefault(x => x.Login == key);
if (target is null)
{
    return ExternalLoginNotFound();
}

var enabledExternalLogins = snapshot.ExternalLogins
    .Where(login => providerCatalog.IsEnabled(login.Login.Provider));
var remainingEnabledExternalLogins = enabledExternalLogins.Count(
    login => login.Login != target.Login);
var hasEnabledPassword = passwordSignInEnabled && snapshot.HasPassword;

if (!hasEnabledPassword && remainingEnabledExternalLogins == 0)
{
    return RejectLastSignInMethodRemoval();
}

var unlinked = await externalLogins.UnlinkAsync(
    new UnlinkExternalLoginCommand(
        currentUser.Id,
        snapshot.Version,
        target.Login),
    ct);
```

The provider subject is trusted host data and should not be serialized to the browser.
Identity reports persisted methods; only the host knows which password flow and OIDC
providers are currently enabled. The last-method policy must count their intersection,
not stale links to disabled providers. Every password and external-login mutation shares
the same user version, so a concurrent change makes `UnlinkAsync` fail with
`identity.concurrency.conflict`. Re-read policy and run a new step-up flow; do not
auto-retry a mutation whose proof or decision was already consumed.

## Email Confirmation and Password Reset

Enable purpose-bound action tokens explicitly:

```csharp
identity.UseDataProtectionActionTokens();
```

Use `IIdentityUserLookupService<TProfile>.FindActiveByEmailAsync` or
`FindActiveByPhoneAsync` for an exact normalized lookup before issuing an account
message. Do not use automatic password-login lookup or the administrative
`IIdentityUserQueryService<TProfile>` contains-search for this workflow:

```csharp
var lookedUp = await users.FindActiveByEmailAsync(request.Email, ct);
if (!lookedUp.IsSuccess)
{
    return AcceptedAccountMessageResponse();
}

var issued = await actionTokens.IssuePasswordResetAsync(
    lookedUp.Value.Id,
    ct);
```

The lookup intentionally returns `identity.user.not_found` to trusted application
orchestration. Anonymous HTTP endpoints must suppress that result and return the same
safe response for known and unknown valid addresses. Rate-limit requests and enqueue
delivery so SMTP/SMS network latency is not part of the anonymous request timing.

Build links from a configured public origin, never an untrusted `Host` header. Keep
action tokens out of logs, telemetry and referrers. Opening a confirmation link should
render a no-store page; use an antiforgery-protected POST to perform the mutation so
mail scanners cannot confirm an address merely by following a link.

Apply password resets through
`IPasswordCredentialService<TProfile>.ResetPasswordAsync` and email confirmations
through `IIdentityUserService<TProfile>.ConfirmEmailAsync`. A successful password reset
rotates the security stamp and invalidates sessions when the host uses online stamp
validation.

## Account Sessions

List active logical sessions for the authenticated user:

```csharp
var listed = await sessions.ListAsync(
    new ListIdentitySessionsCommand(currentUserId),
    ct);
```

The returned `SessionId` identifies the logical refresh chain, not an individual token.
Revoke a selected session with both the authenticated user id and session id:

```csharp
await sessions.RevokeByIdAsync(
    new RevokeIdentitySessionByIdCommand(
        currentUserId,
        selectedSessionId),
    ct);
```

The operation is idempotent and ownership is enforced in the store predicate. Use
`RevokeAllAsync` for "log out everywhere". With stateless bearer validation, an already
issued access token remains valid until expiry. Enable online session validation when
immediate revocation is required.

## Administration Queries

`IIdentityUserQueryService<TProfile>` provides bounded provider-neutral search and
cursor pagination:

```csharp
var page = await userQueries.QueryAsync(
    new IdentityUserQuery(
        Search: request.Search,
        Status: IdentityUserStatus.Active,
        RequiredFlags: UserFlags.None,
        PageSize: 50,
        Cursor: DecodeCursor(request.Cursor)),
    ct);
```

Search matches normalized user name, email and phone fragments, or an exact user
`Guid`. `PageSize` is limited to 100. The host should encode `IdentityUserCursor` as an
opaque URL-safe value rather than expose it as a second offset-based paging contract.

The query service is not authorization. Restrict admin endpoints with application
policies and avoid returning profile fields that the current administrator is not
allowed to inspect.

## Errors and Concurrency

Expected failures use `OperationResult`. Map error type and stable error code to the
host's problem-details format. Useful mappings include:

| Identity outcome | Typical HTTP result |
| --- | --- |
| Validation | `400 Bad Request` |
| Invalid credentials/token | `401 Unauthorized` |
| Forbidden protected-user mutation | `403 Forbidden` |
| Missing resource | `404 Not Found` |
| Duplicate handle/login or stale version | `409 Conflict` |
| Rate limit exceeded | `429 Too Many Requests` |

Do not expose different public login responses for unknown users, absent passwords and
wrong passwords. Return the latest `IdentityUser.Version` to trusted clients that edit
identity state and require it on the next mutation.

## Security Events and Durable Audit

Register an `IIdentitySecurityEventObserver` before `AddSkopkaIdentity` to receive
successful security changes:

```csharp
builder.Services.AddSingleton<
    IIdentitySecurityEventObserver,
    HelloSecurityEventObserver>();
builder.Services.AddSkopkaIdentity<HelloProfile>();
```

The observer callback must enqueue synchronously, return quickly and never throw. Events
contain a stable type, occurrence time, subject user id and optional related resource id.
They intentionally contain no handles, tokens, passwords or provider subjects.

This callback is an observability hook, not a transactional compliance log. For durable
audit, the host should enrich the event with its authenticated actor/correlation context
and write an outbox record in the same transaction as the application operation where
atomicity is required. A queue write performed after an EF commit cannot guarantee that
both records succeed together.

## Endpoint Checklist

- Derive client/rate-limit keys from trusted server context.
- Use generic public responses for login, reset and confirmation requests.
- Require CSRF protection for cookie-authenticated mutations.
- Require reauthentication or step-up before linking identities, changing credentials
  and other sensitive actions.
- Validate return URLs against a host allowlist.
- Never log passwords, action tokens, refresh tokens, OTPs or provider tokens.
- Keep OAuth/OIDC state, nonce and PKCE responsibilities in the protocol adapter.
- Keep domain authorization after authentication and after any step-up decision.
- Schedule bounded session and rate-limit pruning.
- Decide explicitly between short stateless JWT revocation delay and online validation.
