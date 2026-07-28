using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;

namespace Skopka.Identity.RateLimiting;

internal static class IdentityRateLimitErrors
{
    public static Error Exceeded(DateTimeOffset? retryAfter)
        => new(
            IdentityErrorCodes.RateLimitExceeded,
            "Too many requests.",
            ErrorType.Forbidden,
            new RateLimitDetails(retryAfter));
}
