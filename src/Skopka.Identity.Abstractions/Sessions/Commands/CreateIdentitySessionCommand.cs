namespace Skopka.Identity.Sessions;

public sealed record CreateIdentitySessionCommand(
    Guid UserId,
    string SecurityStamp,
    IdentitySessionMetadata? Metadata = null);
