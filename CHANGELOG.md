# Changelog

## 0.18.0

- Added optional host-issued, scope-bound access links with independent expiry, one-use completion, TOTP enrollment and atomic credential recovery. New links supersede prior links; hosts can invalidate existing credentials and sessions at issuance.
- Added trusted session scope and authentication method, persisted across refresh and available to online admission policies. Added a per-account and per-context session lifetime policy with fixed absolute expiry.
- Bound scoped device authorization requests to the approving session's scope and retained its trusted context in the resulting session. Custom device stores must implement scoped operations to use them.
- Added PostgreSQL and SQLite migrations for access links and session and device authorization context. Existing session and device rows have no scope; hosts requiring scope must account for legacy sessions.

## 0.17.0

- Added immutable logical-session assurance and host admission policies for issuance, refresh and online validation. Existing sessions and unmodified stores default to no assurance.

- Added atomic, version-checked verified phone binding for existing users through phone OTP proof verification and binding.
- Added trusted administrative TOTP reset bound to the user version and exact enrollment, removing recovery codes and rotating the security stamp. TOTP enrollment writes now advance the user version; custom factor stores must implement the guarded overloads.

## 0.16.0

- Added a shared phone-number policy with distinct invalid-format and disallowed-country errors. It respects the configured Identity normalizer and PhoneOtpOptions country allowlist.

## 0.15.0

- Added one-time SMS phone sign-in and atomic registration for a verified E.164 phone.
- Extended Verification with userless, purpose-bound phone challenges, one-time proofs, and SQLite/PostgreSQL migrations.
- Added phone OTP rate limits, security events, and a phone sign-in method snapshot.
