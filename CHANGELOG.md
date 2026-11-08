# Changelog

## 0.19.1

- Automatic password login now honors `AuthenticatePasswordCommand.PhoneScope`: when a scope is passed, an entered phone number reaches only the account whose phone is in that scope, so "number + password" works for a number shared by a personal and a staff account. User names and emails still match in every scope. Without a scope the behavior is unchanged. Pass `IdentityPhoneScopes.Default` explicitly for sites that use the default scope.
- Added a scoped `IIdentityUserLookupStore.FindActiveByNormalizedLoginIdentifiersAsync` overload. Custom stores that do not override it fall back to the unscoped lookup, where a shared number stays ambiguous.

## 0.19.0

- Added phone scopes. A trusted host can place a phone in a named scope when creating a user, changing the phone or binding a verified phone, so one number can belong to one account per scope (for example a personal account and a staff account). Phone OTP sign-in, exact phone lookup and phone-handle password login accept the scope; without one they search the default scope `""` only and never choose an account from a named scope. Automatic password login searches every scope, so a number shared across scopes is ambiguous there. User names and emails remain globally unique. `IdentityUser.PhoneScope` reports the scope.
- Added PostgreSQL and SQLite `PhoneScopes` migrations: `phone_scope` (default `''`) on `auth_users` and `identity_login_identifiers`, included in their unique indexes. Existing accounts stay in the default scope with unchanged behavior. Custom stores must persist the scope; custom lookup stores without the scoped overload resolve only the default scope.
- Added role-membership filtering to user queries: `IdentityUserQuery.RoleIds` (any of up to 50 roles) keeps search, status, flags and the `(CreatedAt, Id)` cursor, and `IIdentityUserQueryService.CountAsync` counts matches with the same filter in one database query. Custom query stores must opt in through `SupportsRoleMembershipQueries`; otherwise these queries fail with `identity.user_query.unsupported`.

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
