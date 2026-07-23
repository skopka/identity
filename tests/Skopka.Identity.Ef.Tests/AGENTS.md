# EF Store Test Instructions

Read `../../AGENTS.md` and `../../src/Skopka.Identity.Ef/AGENTS.md` first.

This project verifies the provider-neutral behavior of `Skopka.Identity.Ef`.
Use the EF Core in-memory provider for store contract tests. Keep relational constraints,
SQL generation and SQLSTATE tests in a separate PostgreSQL test project when it is added.

Cover observable store behavior: aggregate persistence, public model mapping, version
increments, timestamps, not-found results and optimistic concurrency conflicts.
