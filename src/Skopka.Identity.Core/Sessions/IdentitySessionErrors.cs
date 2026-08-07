using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;

namespace Skopka.Identity.Sessions;

internal static class IdentitySessionErrors
{
    public static Error SessionInvalid()
        => new(
            IdentityErrorCodes.SessionInvalid,
            "The session is invalid or expired.",
            ErrorType.Unauthorized);

    public static Error AccessTokenInvalid()
        => new(
            IdentityErrorCodes.AccessTokenInvalid,
            "The access token is invalid or expired.",
            ErrorType.Unauthorized);

    public static Error RefreshTokenInvalid()
        => new(
            IdentityErrorCodes.RefreshTokenInvalid,
            "The refresh token is invalid or expired.",
            ErrorType.Unauthorized);

    public static Error RefreshTokenReuseDetected()
        => new(
            IdentityErrorCodes.RefreshTokenReuseDetected,
            "Refresh token reuse was detected and the session was revoked.",
            ErrorType.Unauthorized);
}
