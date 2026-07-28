using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;

namespace Skopka.Identity.StepUp;

internal static class StepUpErrors
{
    public static Error PolicyUnavailable(string action)
        => new(
            IdentityErrorCodes.StepUpPolicyUnavailable,
            "Step-up authorization policy is not available for this action.",
            ErrorType.Forbidden,
            new { action });

    public static Error MethodNotAllowed(string method)
        => new(
            IdentityErrorCodes.StepUpMethodNotAllowed,
            "Verification method is not allowed by the step-up policy.",
            ErrorType.Forbidden,
            new { method });

    public static Error ProofInvalid()
        => new(
            IdentityErrorCodes.VerificationProofInvalid,
            "Verification proof is invalid or expired.",
            ErrorType.Unauthorized);

    public static Error Validation(string field, string message)
        => new(
            IdentityErrorCodes.Validation,
            "Validation failed.",
            ErrorType.Validation,
            new ValidationDetails(new Dictionary<string, string[]>
            {
                [field] = [message]
            }));
}
