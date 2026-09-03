using Skopka.Abstraction.OperationResult;

namespace Skopka.Identity.WebAuthn;

/// <summary>
/// The COSE algorithm an authenticator signs with, by its registered identifier.
/// Only the algorithms this library verifies are named; anything else is
/// refused at registration rather than stored and refused at every sign-in.
/// </summary>
public enum WebAuthnAlgorithm
{
    Es256 = -7,
    Rs256 = -257,
}

/// <summary>
/// What the server already knows about a ceremony it started. The challenge is
/// the value it issued; the origins are the addresses its own pages are served
/// from. Neither comes from the client, which is the whole point of both.
/// </summary>
public sealed record WebAuthnCeremonyExpectation(
    string RelyingPartyId,
    IReadOnlyCollection<string> Origins,
    ReadOnlyMemory<byte> Challenge,
    bool UserVerificationRequired);

/// <summary>
/// A credential as the authenticator described it while registering.
/// <paramref name="PublicKey"/> is a DER SubjectPublicKeyInfo, so that what is
/// stored is a key rather than one protocol's encoding of a key.
/// </summary>
public sealed record WebAuthnAttestedCredential(
    ReadOnlyMemory<byte> CredentialId,
    ReadOnlyMemory<byte> PublicKey,
    WebAuthnAlgorithm Algorithm,
    long SignatureCounter,
    Guid AuthenticatorId,
    bool UserVerified,
    bool BackedUp);

/// <summary>
/// The stored side of an assertion: which key to check the signature with, and
/// what the counter stood at when this credential was last seen.
/// <paramref name="KnownSignatureCounter"/> is null for a credential that has
/// never been used.
/// </summary>
public sealed record WebAuthnAssertionExpectation(
    string RelyingPartyId,
    IReadOnlyCollection<string> Origins,
    ReadOnlyMemory<byte> Challenge,
    bool UserVerificationRequired,
    ReadOnlyMemory<byte> PublicKey,
    WebAuthnAlgorithm Algorithm,
    long? KnownSignatureCounter);

public sealed record WebAuthnAssertionOutcome(
    long SignatureCounter,
    bool UserVerified,
    bool BackedUp);

/// <summary>
/// Reads and checks the two WebAuthn ceremonies. Synchronous and stateless: it
/// is given everything it compares against and touches no storage, so what it
/// answers depends on its arguments alone.
/// </summary>
public interface IWebAuthnCeremonyVerifier
{
    OperationResult<WebAuthnAttestedCredential> ReadRegistration(
        ReadOnlyMemory<byte> clientDataJson,
        ReadOnlyMemory<byte> attestationObject,
        WebAuthnCeremonyExpectation expectation);

    OperationResult<WebAuthnAssertionOutcome> VerifyAssertion(
        ReadOnlyMemory<byte> clientDataJson,
        ReadOnlyMemory<byte> authenticatorData,
        ReadOnlyMemory<byte> signature,
        WebAuthnAssertionExpectation expectation);
}
