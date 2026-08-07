namespace Skopka.Identity.Sessions;

public sealed record StoredIdentitySession(
    Guid SessionId,
    Guid UserId,
    string SecurityStamp,
    long Version,
    DateTimeOffset ExpiresAt,
    DateTimeOffset CreatedAt,
    DateTimeOffset LastRefreshedAt,
    DateTimeOffset? RevokedAt,
    IdentitySessionMetadata? Metadata = null);
