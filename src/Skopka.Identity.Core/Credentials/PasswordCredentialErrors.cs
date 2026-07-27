using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;

namespace Skopka.Identity.Credentials;

public static class PasswordCredentialErrors
{
    public static Error AlreadySet()
        => new(
            IdentityErrorCodes.PasswordAlreadySet,
            "A password is already set for the user.",
            ErrorType.Conflict);

    public static Error NotSet()
        => new(
            IdentityErrorCodes.PasswordNotSet,
            "A password is not set for the user.",
            ErrorType.Conflict);

    public static Error Invalid()
        => new(
            IdentityErrorCodes.InvalidPassword,
            "The password is invalid.",
            ErrorType.Validation);
}
