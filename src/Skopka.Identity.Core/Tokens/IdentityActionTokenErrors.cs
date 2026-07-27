using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;

namespace Skopka.Identity.Tokens;

internal static class IdentityActionTokenErrors
{
    public static Error Invalid()
        => new(
            IdentityErrorCodes.InvalidActionToken,
            "Action token is invalid or expired.",
            ErrorType.Unauthorized);

    public static Error ProviderUnavailable()
        => new(
            IdentityErrorCodes.ActionTokenProviderUnavailable,
            "No identity action token provider is configured.");
}
