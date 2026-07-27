namespace Skopka.Identity.Sessions;

public sealed record IdentityAccessTokenPayload(
    int FormatVersion,
    Guid TokenId,
    Guid UserId,
    Guid SessionId,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt);
