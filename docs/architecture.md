# Architecture

Skopka.Identity separates public identity contracts, orchestration, persistence and
infrastructure adapters. The host application owns transport and business
authorization.

## Module Boundaries

### `Skopka.Identity.Abstractions`

Contains the public API:

- user, credential, verification, session, role and step-up models;
- commands and `OperationResult`-based services;
- store ports used by Core;
- stable error codes;
- normalizer, policy, metrics and validator extension points.

This package has no dependency on EF Core, PostgreSQL or ASP.NET authentication.

### `Skopka.Identity.Core`

Implements identity use cases:

- validation, normalization and mutation policy;
- user and password lifecycle;
- action-token binding;
- verification challenges and one-time proofs;
- session creation, refresh, validation and revocation;
- rate-limit orchestration;
- roles, memberships and step-up decisions.

Core computes operation time and passes it to stores. Expected failures are returned as
errors; infrastructure failures that cannot be translated may still throw.

### `Skopka.Identity.Ef`

Contains provider-neutral EF Core entities, mapping and store implementations. Public
`IdentityUser<TProfile>` instances are mapped from persistence entities and are never
used as EF entities.

### `Skopka.Identity.Ef.PostgreSql`

Owns PostgreSQL-specific behavior:

- `jsonb` application profiles;
- filtered unique indexes for active, non-null handles;
- migration discovery for arbitrary closed `TProfile`;
- translation of PostgreSQL constraint violations into stable identity errors;
- DI registration of all EF stores.

### `Skopka.Identity.Infrastructure`

Contains optional adapters:

- PBKDF2 and Argon2id password hashers;
- ASP.NET Core Data Protection action tokens;
- HMAC-protected generated OTP codes;
- HMAC-obscured rate-limit partitions;
- JWT access tokens, opaque refresh tokens and JwtBearer integration.

### `Skopka.Identity`

Is the consumer-facing composition package. It registers Core defaults and exposes
`IdentityBuilder<TProfile>`. It contains no domain or persistence rules.

## User Aggregate

`IdentityUser<TProfile>` combines:

- stable `Guid` id and application-specific profile;
- nullable display handles and confirmation flags;
- user flags;
- security stamp and optimistic concurrency version;
- delete, block and audit timestamps.

Normalized handles live only in persistence. Display values remain available to the
application.

The generic profile is one type per application. Changing its serialized shape is an
application data migration concern.

## Commands

Commands are use-case input records. They keep method signatures explicit but do not
imply CQRS handlers, a mediator or an event bus.

Most mutations include `ExpectedVersion`. Email and phone confirmation intentionally do
not: their action token is bound to the normalized current handle and security stamp,
which rejects a token issued for a previous value.

## Concurrency and Uniqueness

`IdentityUser.Version` is a database concurrency token. Stores increment it with every
user aggregate mutation. A stale expected version returns
`identity.concurrency.conflict`.

User name, email and phone are unique only for active users and only when non-null.
Soft-deleted users release their handles. Restoring a user can therefore fail with a
duplicate-handle error if another active user took one of those handles.

## Credential Boundary

Profiles never contain password data. Core sees only an opaque verifier string through
`IPasswordCredentialStore<TProfile>`. Hash format, salts, KDF parameters and pepper
selection stay inside the selected hasher.

Password mutations rotate the security stamp. A technical rehash after successful
verification does not rotate it.

## Token and Verification Boundaries

Skopka.Identity uses several intentionally different artifacts:

| Artifact | Purpose |
| --- | --- |
| Action token | Confirm email/phone or authorize password reset |
| OTP response | Answer one verification challenge |
| Verification proof | One-time evidence consumed by a business intent or step-up |
| JWT access token | Short-lived API authentication |
| Refresh token | Rotate one persisted refresh session |
| Step-up decision | In-memory decision for one action/resource pair |

Action tokens are not MFA. OTP verification does not itself grant business permission.
A step-up decision confirms the extra verification requirement but the application must
still enforce its normal authorization policy.

## Sessions and Roles

JWT access tokens contain a security-stamp snapshot and bounded projected claims.
Refresh tokens are stored only as digests and rotate on use. Reuse of a rotated token
revokes the logical session.

Role membership is direct. `ParentId` is hierarchy metadata and does not imply inherited
authorization or inherited JWT claims.

Role and user changes become visible when a new access token is created or refreshed.
Existing stateless access tokens are unchanged until expiry.

## Transaction Boundaries

The library does not claim atomicity across unrelated stores or an application business
mutation. When a step-up decision and business operation must be atomic, the host should
execute both in one unit of work when the stores can share a transaction.

HTTP endpoints, DTOs, cookies, UI, email/SMS delivery and application authorization are
outside the library.
