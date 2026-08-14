using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;

namespace Skopka.Identity.Totp;

internal static class TotpErrors
{
    public static Error AlreadyEnabled()
        => new(
            IdentityErrorCodes.TotpAlreadyEnabled,
            "An authenticator is already enabled.",
            ErrorType.Conflict);

    public static Error NotEnabled()
        => new(
            IdentityErrorCodes.TotpNotEnabled,
            "An authenticator is not enabled.",
            ErrorType.Conflict);

    public static Error EnrollmentInvalid()
        => new(
            IdentityErrorCodes.TotpEnrollmentInvalid,
            "The authenticator enrollment is invalid or expired.",
            ErrorType.Validation);

    public static Error CodeInvalid()
        => new(
            IdentityErrorCodes.TotpCodeInvalid,
            "The authenticator or recovery code is invalid.",
            ErrorType.Unauthorized);

    public static Error SecretUnavailable()
        => new(
            IdentityErrorCodes.TotpSecretUnavailable,
            "The authenticator secret cannot be read.",
            ErrorType.Failure);
}
