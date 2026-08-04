# Build and Test

## Prerequisites

- .NET 10 SDK
- Docker for the PostgreSQL integration test
- Access to the `postgres:17-alpine` image

Restore and build:

```shell
dotnet restore Skopka.Identity.slnx
dotnet build Skopka.Identity.slnx --configuration Release --no-restore
```

Run the complete suite:

```shell
docker pull postgres:17-alpine
dotnet test Skopka.Identity.slnx --configuration Release --no-build
```

The PostgreSQL test is marked with the xUnit `Category=Integration` trait. Run only
non-container tests:

```shell
dotnet test Skopka.Identity.slnx --filter "Category!=Integration"
```

Run only the real PostgreSQL test:

```shell
dotnet test \
  tests/Skopka.Identity.Ef.PostgreSql.Tests/Skopka.Identity.Ef.PostgreSql.Tests.csproj \
  --filter "Category=Integration"
```

The integration test:

- starts an isolated PostgreSQL 17 container;
- applies every packaged migration;
- verifies there are no pending model changes;
- round-trips an application profile through `jsonb`;
- executes real unique constraints and exception mapping;
- verifies active-only filtered indexes across soft delete and restore;
- proves the database concurrency token through two independent contexts.

It never reads a developer connection string and does not fall back to a local database.
If Docker or the image is unavailable, the integration test fails explicitly.

`Skopka.Identity.Ef.Sqlite.Tests` uses an open in-memory SQLite database without
Docker. It applies the packaged migration and exercises JSON profile round-trip,
filtered uniqueness and error mapping, chronological UTC-tick queries, verification
supersession, rate limits, refresh sessions and database concurrency.

## Package Validation

Create all package and symbol artifacts:

```shell
dotnet pack Skopka.Identity.slnx \
  --configuration Release \
  --no-build \
  --output artifacts/packages
```

Expected package ids:

- `Skopka.Identity.Abstractions`
- `Skopka.Identity.Core`
- `Skopka.Identity`
- `Skopka.Identity.Ef`
- `Skopka.Identity.Ef.PostgreSql`
- `Skopka.Identity.Ef.Sqlite`
- `Skopka.Identity.Infrastructure`

Check dependencies for known vulnerabilities:

```shell
dotnet list Skopka.Identity.slnx package \
  --vulnerable \
  --include-transitive \
  --no-restore
```

## Migrations

Restore the repository-local EF tool:

```shell
dotnet tool restore
```

Generate PostgreSQL migrations through the design-time context:

```shell
dotnet tool run dotnet-ef migrations add MigrationName \
  --project src/Skopka.Identity.Ef.PostgreSql \
  --startup-project src/Skopka.Identity.Ef.PostgreSql
```

Generate SQLite migrations through its separate design-time context:

```shell
dotnet tool run dotnet-ef migrations add MigrationName \
  --project src/Skopka.Identity.Ef.Sqlite \
  --startup-project src/Skopka.Identity.Ef.Sqlite
```

After changing the persistence model, update migration discovery, generated SQL,
pending-model, real SQLite and real PostgreSQL tests in the same change.
