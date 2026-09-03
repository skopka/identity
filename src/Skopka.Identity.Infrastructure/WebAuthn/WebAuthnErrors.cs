using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;

namespace Skopka.Identity.Infrastructure.WebAuthn;

internal static class WebAuthnErrors
{
    public static Error ClientDataInvalid()
        => new(
            IdentityErrorCodes.WebAuthnClientDataInvalid,
            "The client data cannot be read.",
            ErrorType.Validation);

    public static Error CeremonyMismatch()
        => new(
            IdentityErrorCodes.WebAuthnCeremonyMismatch,
            "The response answers a different ceremony.",
            ErrorType.Validation);

    public static Error ChallengeMismatch()
        => new(
            IdentityErrorCodes.WebAuthnChallengeMismatch,
            "The response answers a different challenge.",
            ErrorType.Unauthorized);

    public static Error OriginNotAllowed()
        => new(
            IdentityErrorCodes.WebAuthnOriginNotAllowed,
            "The response came from an origin that is not allowed.",
            ErrorType.Unauthorized);

    public static Error RelyingPartyMismatch()
        => new(
            IdentityErrorCodes.WebAuthnRelyingPartyMismatch,
            "The authenticator answered for another relying party.",
            ErrorType.Unauthorized);

    public static Error UserNotPresent()
        => new(
            IdentityErrorCodes.WebAuthnUserNotPresent,
            "The authenticator reported no user presence.",
            ErrorType.Unauthorized);

    public static Error UserNotVerified()
        => new(
            IdentityErrorCodes.WebAuthnUserNotVerified,
            "The authenticator did not verify the user.",
            ErrorType.Unauthorized);

    public static Error AttestationInvalid()
        => new(
            IdentityErrorCodes.WebAuthnAttestationInvalid,
            "The attestation object cannot be read.",
            ErrorType.Validation);

    public static Error AlgorithmNotSupported()
        => new(
            IdentityErrorCodes.WebAuthnAlgorithmNotSupported,
            "The credential uses a signature algorithm this server does not verify.",
            ErrorType.Validation);

    public static Error SignatureInvalid()
        => new(
            IdentityErrorCodes.WebAuthnSignatureInvalid,
            "The assertion signature is invalid.",
            ErrorType.Unauthorized);

    public static Error CounterRegressed()
        => new(
            IdentityErrorCodes.WebAuthnCounterRegressed,
            "The authenticator signature counter did not advance.",
            ErrorType.Unauthorized);
}
