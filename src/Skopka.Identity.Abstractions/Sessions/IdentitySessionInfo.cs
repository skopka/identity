namespace Skopka.Identity.Sessions;

public sealed record IdentitySessionInfo(
    Guid SessionId,
    Guid UserId,
    IdentitySessionMetadata Metadata,
    DateTimeOffset ExpiresAt,
    DateTimeOffset CreatedAt,
    DateTimeOffset LastRefreshedAt);
