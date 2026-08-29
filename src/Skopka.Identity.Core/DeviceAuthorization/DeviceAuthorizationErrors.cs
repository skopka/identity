using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;

namespace Skopka.Identity.DeviceAuthorization;

internal static class DeviceAuthorizationErrors
{
    public static Error Invalid()
        => new(
            IdentityErrorCodes.DeviceAuthorizationInvalid,
            "The device authorization request is invalid or expired.",
            ErrorType.Validation);

    public static Error VerifierInvalid()
        => new(
            IdentityErrorCodes.DeviceAuthorizationVerifierInvalid,
            "The device authorization browser verifier is invalid.",
            ErrorType.Unauthorized);

    public static Error StateInvalid()
        => new(
            IdentityErrorCodes.DeviceAuthorizationStateInvalid,
            "The device authorization request cannot be used in its current state.",
            ErrorType.Conflict);

    public static Error StepUpInvalid()
        => new(
            IdentityErrorCodes.DeviceAuthorizationStepUpInvalid,
            "A fresh matching step-up decision is required.",
            ErrorType.Forbidden);
}
