# WebAuthn credentials

`Skopka.Identity` stores WebAuthn public-key credentials and checks the two
ceremonies a browser performs against them. It does not run the ceremonies: it
neither issues challenges nor decides what a verified assertion is allowed to
do. Those belong to a host such as `Skopka.Hello`, together with the HTTP
endpoints and the page that calls `navigator.credentials`.

The pieces are deliberately separate:

- `IWebAuthnCeremonyVerifier` reads a registration response and verifies an
  assertion. It is synchronous, touches no storage and is given everything it
  compares against, so what it answers depends on its arguments alone.
- `IWebAuthnCredentialStore<TProfile>` persists credentials and records the
  signature counter an accepted assertion reported.

## Registration

```csharp
var identity = services
    .AddSkopkaIdentity<AppProfile>()
    .UsePostgreSql(connectionString)
    .UseWebAuthn();
```

`UsePostgreSql` and `UseSqlite` register the EF credential store; `UseWebAuthn`
registers the verifier.

## What is verified

For both ceremonies:

- the client data parses and names the expected ceremony, so a registration
  response cannot be replayed as a sign-in or the reverse;
- the challenge in the client data equals the challenge the server issued,
  compared in fixed time;
- the origin is one the server serves, compared exactly. This is the check that
  makes a credential useless on a look-alike page;
- the relying party hash in the authenticator data matches the configured
  relying party id;
- user presence is reported, and user verification too when the expectation
  asks for it.

For an assertion, additionally:

- the signature covers `authenticatorData || SHA-256(clientDataJSON)` and
  verifies against the stored public key;
- the signature counter advanced. An authenticator that counts and then repeats
  itself has been copied. One that never counts reports zero for ever, and the
  specification says to accept that rather than to read it as a clone.

## What is not verified

Attestation statements are read but not verified, and `fmt` is ignored.
Deciding that a particular authenticator model made a key means holding a
trusted metadata set and a policy about which models are acceptable, which
belongs to an application rather than to an identity library. The specification
calls attestation optional and expects most relying parties to skip it.

Everything that makes a credential the server's own is still checked: relying
party, origin, challenge, presence and signature.

## Algorithms

`ES256` and `RS256`. Between them they cover the platform authenticators in
Windows, Apple and Android. A credential offering anything else is refused
while registering rather than stored and refused at every sign-in afterwards.

## Storage

`user_webauthn_credentials` holds one row per credential:

- `credential_id` is unique across the table rather than per user. An assertion
  arrives carrying a credential id and nothing else, so the identifier has to
  name one row before it can name a user — this is what lets a passkey sign in
  someone who typed nothing.
- `public_key` is a DER SubjectPublicKeyInfo, so what is stored is a key rather
  than one protocol's encoding of a key, and nothing after registration has to
  know COSE.
- `version` is the optimistic concurrency token. `TryAdvanceCounterAsync`
  answers `false` rather than failing when it moved: that is one assertion
  arriving twice at once, and the caller has already decided the signature is
  good.

## Boundaries

The store keeps what it is told. Whether a counter may move to a given value is
decided by the verifier before the store is called, because that is a rule
about authenticators rather than about rows.
