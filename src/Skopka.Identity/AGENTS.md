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
- `AddSkopkaIdentity<TProfile>()` registers the default security stamp generator and
  rotate/validate service. Consumers may replace the generator by registering first.
- Action tokens remain optional and are enabled through Infrastructure with
  `UseDataProtectionActionTokens<TProfile>()`; the facade does not take a direct Data
  Protection dependency.
