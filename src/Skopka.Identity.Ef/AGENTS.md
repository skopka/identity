# EF Module Instructions

Read `../../AGENTS.md` first. This file narrows the rules for `Skopka.Identity.Ef`.

## Purpose

This module owns EF Core persistence primitives shared by relational/provider-specific
implementations: DbContext, entities, mapping helpers and the EF implementation of
identity stores when it is added.

## Allowed Responsibilities

- Define `IdentityDbContext<TProfile>` and EF entities.
- Implement `EfIdentityUserStore<TProfile>` against `IIdentityUserStore<TProfile>`.
- Implement active normalized-handle lookup through
  `IIdentityUserLookupStore<TProfile>`.
- Implement `EfPasswordCredentialStore<TProfile>` against
  `IPasswordCredentialStore<TProfile>`.
- Implement `EfVerificationChallengeStore<TProfile>` against
  `IVerificationChallengeStore<TProfile>`.
- Implement `EfRateLimitBucketStore<TProfile>` against
  `IRateLimitBucketStore<TProfile>`.
- Implement `EfIdentityRefreshSessionStore<TProfile>` against
  `IIdentityRefreshSessionStore<TProfile>`.
- Implement role CRUD and direct membership stores against
  `IIdentityRoleStore<TProfile>` and `IIdentityUserRoleStore<TProfile>`.
- Implement external-login, aggregate registration and bounded user-query stores.
- Map EF entities to public `IdentityUser<TProfile>` models.
- Configure generic EF relationships, keys, concurrency tokens and timestamps.
- Translate EF concurrency conflicts into identity concurrency errors.

## Boundaries

- Do not enforce high-level domain policy such as `System`/`Protected` mutation checks;
  Core owns those decisions.
- Do not introduce ASP.NET Core auth/sign-in behavior here.
- Keep provider-specific PostgreSQL details in `Skopka.Identity.Ef.PostgreSql` when they
  depend on Npgsql-specific APIs, SQLSTATE values or PostgreSQL-only SQL.
- Do not expose EF entities as public domain models.

## Persistence Rules

- `auth_users` stores normalized handles, confirmation flags, flags, version and
  deleted/blocked/audit timestamps.
- `user_profiles` stores display handles and the generic `Profile`.
- `identity_roles` stores display/normalized names, optional parent metadata, version and
  audit timestamps.
- `identity_user_roles` stores direct memberships with a composite key and assignment
  timestamp.
- `Version` must be configured as an optimistic concurrency token.
- Store operations must update `ModifiedAt` and bump version consistently.
- Soft delete uses `DeletedAt`; normal uniqueness should apply only to non-deleted users.
- Restore may fail if another active user now occupies the same unique handle.

## Store Behavior

- Map duplicate userName/email/phone outcomes to stable identity duplicate errors.
- Map missing users to not-found errors when the store contract returns an
  `OperationResult`.
- Keep password verifier data opaque if credential persistence is implemented here.
- Login lookup filters deleted users in the database query because soft-deleted handles
  may no longer be unique.
- Password verifier replacements compare both user `Version` and the expected previous
  verifier before updating, then bump the user version in the same save operation.
- `auth_users.security_stamp` is required and limited to 64 characters. Explicit stamp
  rotation and password credential changes persist it atomically with the version bump.
- `verification_challenges.version` is a concurrency token. Record-attempt and
  proof-consumption transitions must recheck state, expiry, binding, proof digest and
  expected version before saving.
- `identity_rate_limit_buckets` uses `(scope, key_hash)` as its key. Hit/reset operations
  retry insert/update/delete races and never persist raw account or client identifiers.
- Pruning deletes only buckets older than the supplied cutoff and respects the requested
  batch size.
- `identity_refresh_sessions` stores only refresh-token digests. Rotation atomically
  consumes one token and creates its replacement while preserving logical session,
  user, stamp and absolute expiry bindings.
- Rotated rows remain available for replay detection. Reuse revokes the entire logical
  session; revoke and pruning operations retry optimistic concurrency races.
- Role names are unique by normalized name. Role version is a concurrency token.
  Deleting a role cascades memberships and sets child `ParentId` values to null.
- Removing a missing membership is idempotent; duplicate assignment returns the stable
  role-already-assigned conflict.
- `user_external_logins` uses `(provider, subject)` as its stable key. Link/unlink bumps
  user version and security stamp in the same save.
- Aggregate registration creates user/profile plus credential or external login in one
  `SaveChangesAsync`.
- Active session listing returns one current row per logical chain. Revoke-by-id filters
  both user and session ids.
- User queries apply bounded page size, status/flags/search filters and stable
  `(CreatedAt, Id)` cursor order in the database.
