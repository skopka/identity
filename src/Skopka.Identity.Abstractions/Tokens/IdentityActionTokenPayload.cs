namespace Skopka.Identity.Tokens;

public sealed record IdentityActionTokenPayload(
    int FormatVersion,
    IdentityActionTokenPurpose Purpose,
    Guid UserId,
    string SecurityStamp,
    string? Target,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt);
