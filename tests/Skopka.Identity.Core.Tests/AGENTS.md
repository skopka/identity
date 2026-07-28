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

Verification tests must cover user/purpose/binding/stamp binding, failed-attempt lock,
proof expiry and one-time consumption. Use method-provider and store fakes; do not test
HMAC algorithms in Core.

Step-up tests must cover policy-derived purpose, allowed methods, exact resource
binding, current-policy re-evaluation, verification maximum age and successful
consumption before a decision is returned.

Rate-limit orchestration tests must distinguish account failures from per-request client
hits, preserve dummy password verification on denied account partitions and verify
resend evaluation order.

Session tests must verify stale-stamp rejection, absolute expiry preservation, one-time
refresh rotation, replay family revoke and online access validation after revoke.

Claims tests must cover default user projection, repeated custom roles, reserved claims
and projection failure before session persistence.

Role tests must cover normalization, duplicate names, optimistic concurrency, hierarchy
cycles, protected-user mutation policy and direct-membership claim projection.
