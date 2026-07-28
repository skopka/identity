namespace Skopka.Identity.Sessions;

public sealed record NewRefreshSession(
    Guid TokenId,
    Guid SessionId,
    Guid UserId,
    string TokenHash,
    string SecurityStamp,
    DateTimeOffset ExpiresAt);
