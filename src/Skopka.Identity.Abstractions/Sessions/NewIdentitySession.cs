namespace Skopka.Identity.Sessions;

public sealed record NewIdentitySession(
    Guid SessionId,
    Guid UserId,
    string SecurityStamp,
    DateTimeOffset ExpiresAt,
    IdentitySessionMetadata? Metadata = null);
