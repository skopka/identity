using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;

namespace Skopka.Identity.ExternalLogins;

internal static class ExternalLoginErrors
{
    public static Error NotFound()
        => new(
            IdentityErrorCodes.ExternalLoginNotFound,
            "External login is not linked.",
            ErrorType.NotFound);

    public static Error Duplicate()
        => new(
            IdentityErrorCodes.DuplicateExternalLogin,
            "External login is already linked to another user.",
            ErrorType.Conflict);
}
