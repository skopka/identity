namespace Skopka.Identity.Sessions;

public sealed record IdentitySessionMetadata(
    string? ClientName = null,
    string? DeviceName = null);
