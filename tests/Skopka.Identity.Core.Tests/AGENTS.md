# Core Test Instructions

Read `../../AGENTS.md` and `../../src/Skopka.Identity.Core/AGENTS.md` first.

Test observable Core orchestration with narrow fakes for storage, lookup, hashing and
dummy-verification contracts. Do not depend on EF Core or a concrete password hashing
algorithm here.

Cover security stamp generation, explicit rotation, password-triggered rotation and
validation against user state.

Action-token tests must cover purpose, user, normalized target, security-stamp and expiry
bindings. Password-reset tests must prove that successful stamp rotation prevents token
replay.
