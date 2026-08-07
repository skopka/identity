namespace Skopka.Identity.Sessions;

public sealed record ValidateIdentitySessionCommand(
    Guid UserId,
    Guid SessionId);
