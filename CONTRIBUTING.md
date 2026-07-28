# Contributing

Contributions are welcome while the project is pre-1.0. Keep changes focused and preserve
the module boundaries documented in [docs/architecture.md](docs/architecture.md).

## Development Setup

Requirements:

- .NET 10 SDK
- Docker
- Git

Build and run the complete suite:

```shell
dotnet restore Skopka.Identity.slnx
dotnet build Skopka.Identity.slnx --configuration Release --no-restore
docker pull postgres:17-alpine
dotnet test Skopka.Identity.slnx --configuration Release --no-build
```

See [docs/testing.md](docs/testing.md) for filters, package validation and migration
commands.

## Change Guidelines

- Add public contracts only for a concrete use case.
- Keep transport, UI and delivery concerns outside Core.
- Keep EF and PostgreSQL details outside Abstractions and Core.
- Return stable `OperationResult` errors for expected domain failures.
- Preserve cancellation tokens on asynchronous public APIs.
- Add tests proportional to the security impact and persistence blast radius.
- Update module `AGENTS.md` files when an architectural invariant changes.
- Update README or `docs/` when a consumer-visible API or deployment requirement
  changes.

Do not include unrelated formatting or refactoring in a focused change.

## Persistence Changes

Persistence changes require:

- an EF migration in `Skopka.Identity.Ef.PostgreSql`;
- migration discovery and generated-SQL coverage;
- a clean `HasPendingModelChanges()` check;
- an update to the real PostgreSQL integration test when behavior changes.

Do not edit generated migration metadata manually unless the EF tooling cannot express a
required provider-specific operation and the reason is documented.

## Security Changes

Read [docs/security.md](docs/security.md) before changing credentials, tokens,
verification, sessions or rate limiting.

Security-sensitive changes should include:

- failure-path and boundary tests;
- malformed and oversized input tests;
- rotation or backward-verification behavior where keys/parameters change;
- documentation of new secrets and deployment requirements.

Report vulnerabilities privately according to [SECURITY.md](SECURITY.md).

## Pull Requests

Before opening a pull request:

```shell
dotnet format Skopka.Identity.slnx --no-restore --verify-no-changes
dotnet build Skopka.Identity.slnx --configuration Release --no-restore
dotnet test Skopka.Identity.slnx --configuration Release --no-build
dotnet pack Skopka.Identity.slnx --configuration Release --no-build
```

The repository currently contains a few legacy formatting findings. Do not expand them;
all files changed by a pull request must pass `dotnet format --verify-no-changes`.
