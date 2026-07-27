# Infrastructure Test Instructions

Read `../../AGENTS.md` and `../../src/Skopka.Identity.Infrastructure/AGENTS.md` first.

Credential tests must cover verifier format handling, wrong passwords, parameter
upgrades, pepper rotation and malformed/untrusted verifier input. Reduced work factors
are allowed only in tests to keep the suite fast.
