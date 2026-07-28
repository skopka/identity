using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;

namespace Skopka.Identity.Verification;

internal static class VerificationErrors
{
    public static Error ChallengeInvalid()
        => new(
            IdentityErrorCodes.VerificationChallengeInvalid,
            "Verification challenge is invalid or expired.",
            ErrorType.Validation);

    public static Error ResponseInvalid()
        => new(
            IdentityErrorCodes.VerificationResponseInvalid,
            "Verification response is invalid.",
            ErrorType.Unauthorized);

    public static Error AttemptsExceeded()
        => new(
            IdentityErrorCodes.VerificationAttemptsExceeded,
            "Verification challenge has no attempts remaining.",
            ErrorType.Forbidden);

    public static Error ProofInvalid()
        => new(
            IdentityErrorCodes.VerificationProofInvalid,
            "Verification proof is invalid or expired.",
            ErrorType.Unauthorized);

    public static Error MethodUnavailable(string method)
        => new(
            IdentityErrorCodes.VerificationMethodUnavailable,
            "The verification method is not configured.",
            ErrorType.Validation,
            new { method });

    public static Error Blocked()
        => new(
            IdentityErrorCodes.AuthenticationBlocked,
            "Authentication is blocked.",
            ErrorType.Forbidden);
}
