# Changelog

## 0.16.0

- Added a shared phone-number policy with distinct invalid-format and disallowed-country errors. It respects the configured Identity normalizer and PhoneOtpOptions country allowlist.

## 0.15.0

- Added one-time SMS phone sign-in and atomic registration for a verified E.164 phone.
- Extended Verification with userless, purpose-bound phone challenges, one-time proofs, and SQLite/PostgreSQL migrations.
- Added phone OTP rate limits, security events, and a phone sign-in method snapshot.
