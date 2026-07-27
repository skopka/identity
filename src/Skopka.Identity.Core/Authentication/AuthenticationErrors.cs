using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;

namespace Skopka.Identity.Authentication;

public static class AuthenticationErrors
{
    public static Error InvalidCredentials()
        => new(
            IdentityErrorCodes.InvalidCredentials,
            "The login or password is invalid.",
            ErrorType.Unauthorized);

    public static Error Blocked()
        => new(
            IdentityErrorCodes.AuthenticationBlocked,
            "Authentication is blocked for the user.",
            ErrorType.Forbidden);
}
