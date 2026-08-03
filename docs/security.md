# Security Model

This document describes the intended boundaries and deployment requirements. It is not
a substitute for an application-specific threat model or independent security review.

## Passwords

- New passwords default to 15 through 128 Unicode code points.
- Applications with mandatory MFA may lower the configured minimum to 8.
- The maximum cannot be configured below 64 or above 1024.
- Passwords are not trimmed, normalized or subjected to upper/digit/symbol rules.
- Oversized input is rejected before a real or dummy KDF operation.
- Existing passwords are checked against the maximum but not the current minimum, so a
  legacy short password can still be authenticated and replaced.
- `IPasswordValidator<TProfile>` can add asynchronous blocklist or breached-password
  checks after the caller has established authority for the mutation.

PBKDF2-HMAC-SHA256 is available without an application secret. The Argon2id provider
first applies HMAC-SHA256 with an application-managed pepper and then runs Argon2id.

Do not log passwords, verifier strings, pepper material or password-reset tokens.

Automatic login generates at most three distinct normalized candidates and queries the
active login-identifier registry once. Inputs longer than 512 characters are rejected
before account/client rate limiting. Zero matches and matches spanning multiple users
use the same invalid-credentials response and one dummy password-verification workload;
do not add follow-up probes that reveal which handle collided.

The default phone login policy accepts only 8-15 ASCII digits with optional leading `+`
and spaces, `-`, `(`, `)` or `.` separators. It is shared by persistence, confirmation,
action-token binding, exact lookup and explicit/automatic password login. Override
`IIdentityNormalizer.NormalizePhoneLoginIdentifier` for a different numbering plan;
do not normalize arbitrary letter-containing input into a phone login key.

## Secret Inventory

Use independent random keys for each purpose:

| Secret | Minimum / storage requirement |
| --- | --- |
| Password pepper | At least 32 bytes, secret manager or HSM-backed provider |
| JWT signing key | At least 32 bytes, shared by issuers and validators |
| OTP HMAC key | At least 32 bytes, retained through challenge expiry |
| Rate-limit HMAC partition key | At least 32 bytes per version, shared by database writers during overlap |
| Data Protection key ring | Persisted and protected outside the application database |

Never reuse one key for multiple rows in this table.

Pepper, OTP and rate-limit HMAC providers support key ids so historical keys can remain
available during rotation. Remove an old pepper or OTP key only after no valid verifier
or challenge can reference it.

Rotating a JWT signing key invalidates every access token signed only by the old key.
Plan overlap or coordinated rollout at the application layer if uninterrupted
validation is required.

## Action Tokens

Email confirmation, phone confirmation and password reset use ASP.NET Core Data
Protection. Tokens are bound to:

- action purpose;
- user id;
- current security stamp;
- current normalized handle when applicable;
- issue and expiry times.

Persist and share the Data Protection key ring across replicas. An ephemeral key ring
invalidates outstanding tokens after restart and makes tokens instance-specific.

Action tokens are bearer secrets but are not OTP or MFA authenticators.

## Verification and Step-Up

Verification challenges bind the user, server-created purpose, intent binding, method
and current security stamp. Failed-attempt limits and expiry are enforced independently
of the verification method.

A resend is latest-wins for the exact `(user, purpose, binding, method)` tuple. The
store atomically supersedes earlier `Pending` and `Verified` challenges before creating
the replacement; different intents coexist. PostgreSQL serializes issuance on the user
row and enforces one active intent through a filtered unique SHA-256 intent index. This
lock does not change the user's optimistic `Version`.

Core persists only a SHA-256 digest of the high-entropy verification proof. Proofs are
one-time and short-lived.

Step-up policy owns the required verification purpose, assurance and permitted methods.
The business use case owns the action/resource binding. Do not accept either value
unmodified from an untrusted client.

A successful step-up decision does not replace role or domain authorization.

## JWT and Refresh Sessions

Access tokens should remain short-lived. With default stateless JwtBearer validation:

- a signed token remains usable until expiry;
- password/security-stamp changes do not immediately revoke that token;
- role changes do not rewrite existing claims.

Enable `ValidateSessionOnEveryRequest` when every request must verify the persisted
session and current user state. This provides faster revocation at the cost of a database
lookup.

Refresh tokens are random opaque secrets. Persistence stores digests, rotation state
and the security-stamp snapshot, never plaintext tokens. Reuse of a rotated token revokes
the complete logical session.

Session client/device values are untrusted display labels. Do not store raw IP addresses
in them or use them for security decisions. Revoke-by-id filters on both user and session
id.

## External Logins

Skopka.Identity stores only a canonical provider name and exact stable provider subject.
The consuming OAuth/OIDC client owns state, nonce, PKCE, token validation and subject
extraction. Never resolve, register or link from a provider/subject pair submitted
directly by an untrusted client.

Do not auto-link accounts based only on matching email addresses. Explicit linking
should require an authenticated account and the host's step-up policy. Link and unlink
rotate the security stamp.

Only an authorized trusted-host workflow should call the sign-in-method snapshot query.
Use `HasPassword` and external-login keys to enforce a host-owned last-method rule, but
count only password sign-in and providers currently enabled by the host. A persisted
link to a disabled provider is not an available sign-in method. Pass the snapshot
version to the mutation and never return provider subjects from an HTTP endpoint or UI
model. Treat a concurrency conflict as a fresh operation requiring policy and step-up
re-evaluation, not as permission to retry automatically.

## Security Events and Audit

`IIdentitySecurityEventObserver` receives successful state-change notifications without
credentials, tokens, handles or provider subjects. Implementations must enqueue quickly
and must not throw.

The observer is not a durable audit log: its callback occurs after the identity store
commit. Compliance-sensitive hosts should use a transactional outbox in their own unit
of work and enrich records with authenticated actor and request correlation context.

## Rate Limiting

The host creates trusted account/client partition inputs. Raw IP addresses or request
body values should not be persisted directly. The HMAC partition adapter obscures values
before storage but does not make low-entropy values safe to expose.

Client partitions count every request. Account partitions count credential failures and
reset only after a correct password.

The persisted rate-limit bucket key is `(scope, partition_version, key_hash)`.
`partition_version` describes the configured partition derivation and is not specific
to HMAC, so custom `IRateLimitPartitionHasher` implementations must also expose stable
versions. Raw account and client identifiers remain outside persistence.

Rotate an HMAC partition key as follows:

1. Configure the new and previous `(version, key)` pairs on every new replica and make
   the new version current.
2. Keep at least one previous version shared with every old-only replica. Successful
   hits are written to all configured versions, preserving one effective counter across
   the rolling deployment.
3. Remove old-only replicas, wait at least the longest configured active rate-limit
   window, and only then remove the previous key.

A deployment with no overlapping version cannot preserve active counters. Do not rename
or reuse a version for different key material. Existing pre-rotation rows are migrated
as version `legacy`; the original single-key overload continues to use that version.

## Protected Users

`System` and `Protected` users cannot be changed through normal APIs. This policy is a
domain guard, not a replacement for endpoint authorization.

Soft delete hides users from active handle lookup but retains their data. Decide at the
application level when legal or operational requirements require irreversible erasure.

## Deployment Checklist

- Store every key outside source control and ordinary application settings.
- Use TLS for PostgreSQL and all public endpoints.
- Run packaged migrations as a controlled deployment step.
- Back up and test restoration of the database and Data Protection key ring together.
- Configure short JWT lifetimes appropriate to stateless revocation delay.
- Enable online session validation for endpoints that require immediate revocation.
- Configure persistent account and client rate limiting.
- Register a breached-password/blocklist validator.
- Keep logs free of credentials, tokens, OTP values and sensitive profile fields.
- Protect confirmation, reset, refresh and verification endpoints against CSRF and
  enumeration at the transport layer.
- Perform application authorization after authentication and step-up checks.
- Monitor duplicate conflicts, rate-limit decisions, verification failures and refresh
  token reuse without recording submitted secrets.
- Run the PostgreSQL integration test against every supported PostgreSQL major version
  before claiming compatibility.

## Known Gaps

The current pre-1.0 release does not include:

- built-in OAuth/OIDC protocol clients;
- TOTP;
- WebAuthn/passkeys;
- recovery codes;
- cookie sign-in;
- controllers, Razor UI or delivery adapters;
- automatic JWT signing-key overlap;
- a built-in breached-password data source.

Applications that require these capabilities must provide them outside the current
library or wait for the corresponding contracts and adapters.
