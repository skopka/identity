# EF Store Test Instructions

Read `../../AGENTS.md` and `../../src/Skopka.Identity.Ef/AGENTS.md` first.

Verification store tests must cover failed-attempt state transitions, proof binding,
single consumption and optimistic concurrency behavior.

Rate-limit store tests must cover fixed-window limits, window rollover, cooldown without
extension on denied hits, reset, bounded pruning and concurrency-token model
configuration.

Refresh-session store tests must cover atomic replacement, rotated-token replay,
digest mismatch, family revoke and bounded pruning.

Role store tests must cover version increments, stale versions, direct membership
add/list/check/remove, duplicate assignment and role-delete cascade behavior.

This project verifies the provider-neutral behavior of `Skopka.Identity.Ef`.
Use the EF Core in-memory provider for store contract tests. Keep relational constraints,
SQL generation and SQLSTATE tests in a separate PostgreSQL test project when it is added.

Cover observable store behavior: aggregate persistence, public model mapping, version
increments, timestamps, not-found results and optimistic concurrency conflicts.
