# PostgreSQL EF Test Instructions

Read `../../AGENTS.md`, `../../src/Skopka.Identity.Ef/AGENTS.md` and
`../../src/Skopka.Identity.Ef.PostgreSql/AGENTS.md` first.

Keep migration discovery, generated SQL and pending-model tests current when the
verification challenge schema changes.

This project verifies PostgreSQL-specific EF model annotations and exception mapping.
Tests that require a live PostgreSQL server should be explicit integration tests and
must not silently depend on a developer-local database.
