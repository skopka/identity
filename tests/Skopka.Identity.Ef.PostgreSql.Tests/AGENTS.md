# PostgreSQL EF Test Instructions

Read `../../AGENTS.md`, `../../src/Skopka.Identity.Ef/AGENTS.md` and
`../../src/Skopka.Identity.Ef.PostgreSql/AGENTS.md` first.

Keep migration discovery, generated SQL and pending-model tests current when the
verification challenge schema changes.

Keep the same migration checks current for `identity_rate_limit_buckets`.

Keep refresh-session entity metadata, store registration and latest migration SQL
covered.

Keep role entity metadata, normalized-name uniqueness, constraint mapping, store
registration and role migration SQL covered.

DI registration tests should cover optional StepUp service/policy composition. StepUp
does not add a PostgreSQL entity or migration; it consumes existing Verification state.

This project verifies PostgreSQL-specific EF model annotations and exception mapping.
Tests that require a live PostgreSQL server should be explicit integration tests and
must not silently depend on a developer-local database.
