using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;

namespace Skopka.Identity.WebAuthn;

internal static class WebAuthnServiceErrors
{
    public static Error CredentialNotFound()
        => new(
            IdentityErrorCodes.WebAuthnCredentialNotFound,
            "The credential was not found.",
            ErrorType.NotFound);

    /// <summary>
    /// Deliberately the same answer as a bad signature. An assertion is offered
    /// before anyone is known, so telling a caller that a credential id is
    /// unknown would answer a question they had no right to ask.
    /// </summary>
    public static Error AssertionRejected()
        => new(
            IdentityErrorCodes.WebAuthnSignatureInvalid,
            "The assertion is invalid.",
            ErrorType.Unauthorized);

    public static Error TooManyCredentials(int limit)
        => new(
            IdentityErrorCodes.WebAuthnTooManyCredentials,
            $"At most {limit} credentials can be registered.",
            ErrorType.Conflict);
}
