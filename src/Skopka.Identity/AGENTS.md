# Facade Module Instructions

Read `../../AGENTS.md` first. This file narrows the rules for the `Skopka.Identity`
facade package.

## Purpose

This module is the consumer-facing composition layer. It should make the library easy to
install and configure without moving domain or persistence logic into the facade.

## Allowed Responsibilities

- Provide DI extension methods such as `AddSkopkaIdentity<TProfile>()`.
- Register Core services, default policies, normalizers and metrics.
- Expose options objects for consumer configuration.
- Delegate persistence registration to EF/provider-specific modules.
- Provide ASP.NET Core integration surface when the project intentionally becomes a
  lightweight Microsoft Identity replacement.

## Boundaries

- Do not implement business rules here.
- Do not implement EF store logic here.
- Do not define core public models here unless this project intentionally re-exports or
  composes abstractions.
- Do not hide important configuration behind magic defaults that cannot be overridden.

## Consumer Experience Rules

- Prefer one clear setup path for the common case.
- Keep extension method names predictable and discoverable.
- Make optional subsystems explicit: EF persistence, PostgreSQL, password credentials,
  tokens, external login, roles and claims.
- Defaults should be safe, but every security-sensitive behavior must be configurable.
- Password hashing is selected explicitly with `UsePbkdf2PasswordHasher()` or
  `UseArgon2idPepperedPasswordHasher()`. Do not register a hidden password-hashing
  default in `AddSkopkaIdentity<TProfile>()`.
- Selecting a password hasher activates password credential and authentication services;
  the configured persistence provider must supply their stores.
- `AddSkopkaIdentity<TProfile>()` registers safe default `PasswordPolicyOptions`.
  Consumers configure length bounds with `ConfigurePasswordPolicy()` and add
  application checks with `AddPasswordValidator<TValidator>()`.
- `AddSkopkaIdentity<TProfile>()` registers the default security stamp generator and
  rotate/validate service. Consumers may replace the generator by registering first.
- Action tokens remain optional and are enabled through Infrastructure with
  `UseDataProtectionActionTokens<TProfile>()`; the facade does not take a direct Data
  Protection dependency.
- `AddSkopkaIdentity<TProfile>()` registers Verification orchestration and default
  options. Concrete verification methods remain optional and are selected through
  Infrastructure extensions such as `UseHmacOneTimeCodes<TProfile>()`.
- Step-up authorization remains optional and is enabled with
  `AddStepUpAuthorization<TPolicyProvider>()`. The application supplies the policy
  provider; the facade registers only Core orchestration.
- Persistent rate limiting remains optional and is enabled through Infrastructure with
  `UseHmacRateLimiting<TProfile>()` or a custom adapter through
  `UseRateLimiting<TProfile>()`. `AddSkopkaIdentity<TProfile>()` registers only its
  default policy options so existing consumers continue to work without a limiter.
- JWT sessions remain optional and are enabled through Infrastructure with
  `UseJwtSessions<TProfile>()`. The configured persistence provider supplies the refresh
  session store; the facade registers only default session lifetime options. Hosts may
  configure a current JWT key id plus a bounded overlapping key set for rotation.
- The default session claims provider projects user handles and confirmation state.
  Applications attach role/domain projections with
  `IdentityBuilder<TProfile>.AddSessionClaimsProvider<TProvider>()`.
- Roles remain optional and are enabled with `IdentityBuilder<TProfile>.AddRoles()`.
  This registers role orchestration, bounded role queries and the direct-membership JWT
  claims provider; persistence adapters provide the stores.
- Role changes are visible in newly created or refreshed access tokens. Existing JWTs
  keep their embedded role claims until expiry. Session revocation invalidates them
  immediately only when online session validation is enabled.
- ASP.NET Core bearer setup remains in the optional Infrastructure package through
  `UseJwtBearerAuthentication<TProfile>()`; hosts own middleware ordering and
  authorization policies.
- Core registration, external-login lifecycle, sign-in-method snapshots, exact
  active-user lookup and bounded user-query services are registered by
  `AddSkopkaIdentity<TProfile>()`; PostgreSQL supplies their stores.
- Register a noop security-event observer by default with `TryAdd`. Hosts may register
  their observer first; callbacks are observability hooks, not a durable audit store.
