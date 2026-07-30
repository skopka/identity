namespace Skopka.Identity.Sessions;

public sealed record StoredRefreshSession(
    Guid TokenId,
    Guid SessionId,
    Guid UserId,
    string TokenHash,
    string SecurityStamp,
    long Version,
    DateTimeOffset ExpiresAt,
    DateTimeOffset CreatedAt,
    DateTimeOffset ModifiedAt,
    DateTimeOffset? RotatedAt,
    DateTimeOffset? RevokedAt,
    Guid? ReplacedByTokenId,
    IdentitySessionMetadata? Metadata = null);
