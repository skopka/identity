namespace Skopka.Identity.Sessions;

public sealed record RegisterIdentitySessionCommand(
    Guid UserId,
    string SecurityStamp,
    IdentitySessionMetadata? Metadata = null);
