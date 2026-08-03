# PostgreSQL EF Module Instructions

Read `../../AGENTS.md` first. This file narrows the rules for
`Skopka.Identity.Ef.PostgreSql`.

## Purpose

This module owns PostgreSQL-specific EF Core integration for `Skopka.Identity`.

## Allowed Responsibilities

- Add Npgsql/PostgreSQL-specific model configuration.
- Configure PostgreSQL table/column names and filtered unique indexes.
- Configure `TProfile` persistence as `jsonb` where PostgreSQL-specific mapping is
  required.
- Translate PostgreSQL unique violations into identity duplicate errors.
- Provide PostgreSQL DI extension methods for EF persistence when the facade needs them.
- Register user, active login lookup and password credential EF stores through
  `UsePostgreSql`.
- Register `IVerificationChallengeStore<TProfile>` through `UsePostgreSql`.
- Register `IRateLimitBucketStore<TProfile>` through `UsePostgreSql`.
- Register `IIdentityRefreshSessionStore<TProfile>` through `UsePostgreSql`.
- Register role and user-role stores through `UsePostgreSql`.
- Register external-login, aggregate-registration and user-query stores through
  `UsePostgreSql`.

## Boundaries

- Do not implement Core business policy here.
- Do not duplicate generic EF entity definitions unless provider-specific mapping truly
  requires it.
- Do not add ASP.NET Core sign-in/cookie behavior here.
- Do not leak PostgreSQL exceptions into public abstraction contracts.

## PostgreSQL Rules

- Unique indexes for handles should apply only when the user is not deleted and the
  normalized handle is not null:
  - `normalized_user_name`
  - `normalized_email`
  - `normalized_phone`
- PostgreSQL unique violation SQLSTATE `23505` should be translated to the appropriate
  duplicate identity error.
- `identity_login_identifiers.normalized_key` has one active owner across all handle
  types through the stable filtered unique index
  `ux_identity_login_identifiers_active_normalized_key`; conflicts map to
  `identity.login_identifier.duplicate`.
- Keep index names stable so exception mapping can identify which handle failed.

## Migrations

- Packaged migrations live in `Migrations`.
- Restore the repository-local EF tool with `dotnet tool restore`.
- Generate migrations through `PostgreSqlIdentityDesignTimeDbContextFactory` using
  `dotnet tool run dotnet-ef`.
- Do not remove `PostgreSqlIdentityMigrationsAssembly`: standard EF discovery filters
  migrations by the closed generic design-time context and would hide them from a
  runtime context using another `TProfile`.
- Keep tests for `GetMigrations()`, generated migration SQL and
  `HasPendingModelChanges()`.
- Security stamp migration backfills existing users with PostgreSQL-generated UUID values
  before making the column non-null.
- Verification migrations create `verification_challenges` with a foreign key to
  `auth_users`, a user/state lookup index and a concurrency-token version column. The
  superseding migration backfills the length-prefixed SHA-256 `intent_hash`, safely
  supersedes duplicate active legacy rows and adds the filtered unique active-intent
  index `ux_verification_challenges_active_intent`.
- Rate-limit migrations create `identity_rate_limit_buckets` with a composite
  `(scope, partition_version, key_hash)` primary key and backfill pre-rotation rows with
  the `legacy` version.
- Session migrations create `identity_refresh_sessions` with token/session/user lookup
  indexes, digest-only token storage and an optimistic concurrency version.
- Role migrations create `identity_roles` and `identity_user_roles`, with a unique
  normalized role-name index and stable key/foreign-key names used by exception mapping.
- External-login constraints use stable lowercase names for exception mapping. Session
  metadata columns are bounded nullable display labels.
- Login-identifier migrations backfill the default normalizer's direct keys,
  formatted-phone alias and phone-shaped raw-handle aliases before creating the filtered
  active-key uniqueness constraint. The packaged preflight rejects oversized handles
  and legacy phone rows outside the default policy. Deployments with a custom
  `IIdentityNormalizer` or phone-login policy must replace or extend the validation and
  backfill after a normalizer-specific preflight.
