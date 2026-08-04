# SQLite EF Module Instructions

Read `../../AGENTS.md` and `../Skopka.Identity.Ef/AGENTS.md` first.

This module owns SQLite-specific EF Core integration, exception mapping and packaged
migrations. Keep generic stores and entities in `Skopka.Identity.Ef`.

- Store `DateTimeOffset` values as UTC ticks in `INTEGER` columns so ordering and range
  predicates have chronological SQLite semantics.
- Keep filtered unique indexes aligned with the PostgreSQL provider and use stable names.
- Package migrations and preserve migration discovery for arbitrary `TProfile` types.
- Translate known SQLite unique violations to stable identity errors without leaking
  provider exceptions through public store contracts.
- Tests use a real in-memory SQLite database with foreign keys enabled.
