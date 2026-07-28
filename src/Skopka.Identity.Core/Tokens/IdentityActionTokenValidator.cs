using Skopka.Abstraction.OperationResult;

namespace Skopka.Identity.Tokens;

internal static class IdentityActionTokenValidator
{
    public const int CurrentFormatVersion = 1;

    public static Error? Validate(
        IIdentityActionTokenProvider? provider,
        string? token,
        IdentityActionTokenPurpose purpose,
        Guid userId,
        string securityStamp,
        string? target,
        DateTimeOffset now)
    {
        if (provider is null)
        {
            return IdentityActionTokenErrors.ProviderUnavailable();
        }

        if (string.IsNullOrWhiteSpace(token)
            || !provider.TryRead(token, purpose, out var payload)
            || payload is null
            || payload.FormatVersion != CurrentFormatVersion
            || payload.Purpose != purpose
            || payload.UserId != userId
            || !string.Equals(
                payload.SecurityStamp,
                securityStamp,
                StringComparison.Ordinal)
            || !string.Equals(payload.Target, target, StringComparison.Ordinal)
            || payload.ExpiresAt <= payload.IssuedAt
            || payload.ExpiresAt <= now)
        {
            return IdentityActionTokenErrors.Invalid();
        }

        return null;
    }
}
