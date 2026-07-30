namespace Skopka.Identity.Sessions;

public sealed record RevokeIdentitySessionByIdCommand(
    Guid UserId,
    Guid SessionId);
