# Migrating From ASP.NET Core Identity

Skopka.Identity is not API-compatible with ASP.NET Core Identity. Migration is a data
and application-flow change, not a package rename.

Review the current
[ASP.NET Core Identity overview](https://learn.microsoft.com/aspnet/core/security/authentication/identity?view=aspnetcore-10.0)
alongside this guide and inventory every feature the application uses.

## Capability Mapping

| ASP.NET Core Identity | Skopka.Identity |
| --- | --- |
| `UserManager<TUser>` user mutations | `IIdentityUserService<TProfile>` |
| Password methods on `UserManager<TUser>` | `IPasswordCredentialService<TProfile>` |
| `HasPasswordAsync` and `GetLoginsAsync` | `IIdentitySignInMethodQueryService<TProfile>` |
| `SignInManager<TUser>.PasswordSignInAsync` | `IPasswordAuthenticationService<TProfile>` plus host session creation |
| `RoleManager<TRole>` | `IIdentityRoleService<TProfile>` |
| User-role membership | `IIdentityRoleService<TProfile>` |
| `IdentityDbContext` | `PostgreSqlIdentityDbContext<TProfile>` |
| Security stamp | `IdentityUser.SecurityStamp` |
| Concurrency stamp | Numeric `IdentityUser.Version` |
| Lockout | `BlockedAt` / `BlockedUntil` plus persistent rate limiting |
| Identity cookies | Host-owned; optional Skopka JWT sessions are not cookie-compatible |
| Identity UI | Host-owned |
| External login tables | `IExternalLoginService<TProfile>` and `user_external_logins` |
| Authenticator TOTP / recovery codes | Not yet implemented |

Custom Microsoft user claims do not automatically become Skopka session claims. Project
them through `IIdentitySessionClaimsProvider<TProfile>` or keep domain authorization in
the application.

## Migration Blockers

Do not cut over yet if the application requires any current gap:

- built-in OAuth/OIDC protocol clients when no host adapter can be added;
- authenticator TOTP;
- WebAuthn/passkeys;
- recovery codes;
- existing Identity cookies to remain valid;
- existing Microsoft email/reset tokens to remain valid;
- APIs written directly against `UserManager`, `SignInManager` or Identity EF entities
  that cannot be changed.

Use parallel operation or implement the missing adapter before migrating these users.

## Data Mapping

A typical mapping from `AspNetUsers` is:

| Microsoft user field | Skopka target |
| --- | --- |
| `Id` | `auth_users.id` after converting to `Guid` |
| `UserName` | `user_profiles.user_name` |
| `NormalizedUserName` | `auth_users.normalized_user_name` |
| `Email` | `user_profiles.email` |
| `NormalizedEmail` | `auth_users.normalized_email` |
| `EmailConfirmed` | `auth_users.email_confirmed` |
| `PhoneNumber` | `user_profiles.phone` |
| Normalized phone | Recompute with the configured `IIdentityNormalizer` |
| `PhoneNumberConfirmed` | `auth_users.phone_confirmed` |
| `SecurityStamp` | `auth_users.security_stamp` |
| `LockoutEnd` | `auth_users.blocked_until` with a matching `blocked_at` |
| Application user fields | Serialized `user_profiles.profile` |
| `PasswordHash` | `user_credentials.password_verifier` through a compatibility plan |

Map provider names and stable provider keys from `AspNetUserLogins` to
`user_external_logins.provider` and `user_external_logins.subject`. Provider names are
canonicalized by Core; subjects remain case-sensitive. Validate source lengths against
`ExternalLoginLimits` and preserve the original provider key exactly.

Initialize `Version` to 1. Do not copy `ConcurrencyStamp` into `Version`; they have
different types and semantics.

Skopka user ids are `Guid`. Applications using string or integer Microsoft Identity ids
need an explicit stable id mapping. Preserve that mapping for foreign keys in application
tables.

Normalize every raw handle with the same normalizer the new application will use before
loading data. Insert the distinct union of every automatic candidate plus the exact
normalized user name, email and phone into `identity_login_identifiers`, with
`is_active` false only for soft-deleted users. Resolve both same-handle and cross-handle
duplicates before adding active filtered unique indexes; for example, one user's email
cannot remain another active user's user name when automatic login is enabled.

The packaged PostgreSQL migration backfills aliases produced by
`DefaultIdentityNormalizer`, including formatted-phone aliases and phone-shaped user
name/email values. Its preflight rejects handles over 512 characters and legacy phone
rows that do not match the default 8-15 digit policy or its normalized value. Clean
those rows before upgrading. If the application replaces `IIdentityNormalizer` or
overrides `NormalizePhoneLoginIdentifier`, run a preflight with that implementation and
replace or extend the migration validation/backfill so every raw handle contributes its
complete automatic candidate set. The filtered unique-index creation intentionally
fails when existing active users still share any resulting key.

Map direct role memberships to `identity_roles` and `identity_user_roles`. Role parent
metadata does not create inherited membership or authorization.

## Password Migration

Skopka verifier formats are different from the default Microsoft Identity format.
Copying `PasswordHash` into `password_verifier` without a compatibility hasher makes the
password unusable.

Choose one strategy.

### Forced Reset

1. Import users without password credentials.
2. Revoke old cookies and sessions.
3. Send a password-reset flow using the new action-token system.
4. Create the Skopka verifier after successful reset.

This is operationally simple but forces every password user through recovery.

### Rehash on Successful Login

Temporarily register an `IPasswordHasher` adapter that:

1. recognizes and verifies the current Skopka format first;
2. falls back to Microsoft's `PasswordHasher<TUser>` for a legacy verifier;
3. returns `PasswordVerificationResult.SuccessRehashNeeded` when the legacy verifier is
   valid;
4. creates all new verifiers with the selected Skopka PBKDF2 or Argon2id provider.

Skopka authentication atomically replaces a verifier after
`SuccessRehashNeeded`. Keep the compatibility adapter until the migration window closes,
then force reset any remaining legacy credentials.

Microsoft's password hasher exposes the same successful-but-rehash concept in its
[`PasswordVerificationResult`](https://learn.microsoft.com/dotnet/api/microsoft.aspnetcore.identity.passwordverificationresult?view=aspnetcore-10.0).

Test the adapter with real hashes from every Microsoft Identity compatibility mode used
by the application. Do not infer the format from production data without fixtures.

## Token and Session Cutover

Assume these artifacts become invalid at cutover:

- Identity application cookies;
- security-stamp validation cookies;
- email-confirmation tokens;
- password-reset tokens;
- two-factor provider tokens;
- remember-browser cookies.

Skopka action tokens have different purpose and payload binding. JWT sessions use a
separate signing key and refresh-session store.

A safe cutover normally:

1. stops writes to the old identity store;
2. migrates users, roles and compatible credentials;
3. rotates the application authentication scheme;
4. requires users to authenticate again;
5. issues only new confirmation, reset and session artifacts;
6. monitors invalid credential, reset and duplicate-handle rates.

## Application Refactoring

Move HTTP concerns into the host:

- registration endpoint calls `IIdentityRegistrationService<TProfile>` so the user and
  first sign-in method are persisted atomically;
- login endpoint authenticates and explicitly creates the chosen host session;
- logout revokes a refresh session or clears the host cookie;
- email/SMS delivery sends values returned by action-token or verification services;
- authorization policies remain application-owned.

Do not expose persistence stores directly from controllers. Stores are Core ports and
do not enforce the complete use-case policy.

## Recommended Rollout

1. Inventory Identity features, custom stores, tokens, claims and user fields.
2. Build the Skopka profile type and id mapping.
3. Rehearse migration against a production-shaped database copy.
4. Verify duplicate normalization and role mappings.
5. Choose forced reset or compatibility rehash.
6. Run both unit tests and the real PostgreSQL integration test.
7. Deploy behind a limited cohort or maintenance window.
8. Monitor and retain a database rollback point.
9. Remove legacy hash verification only after the agreed migration window.

Never run destructive migration scripts against the only copy of the identity database.
