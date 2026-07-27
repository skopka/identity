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
