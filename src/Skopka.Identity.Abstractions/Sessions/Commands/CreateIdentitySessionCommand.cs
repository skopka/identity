namespace Skopka.Identity.Sessions;

public sealed record CreateIdentitySessionCommand(
    Guid UserId,
    string SecurityStamp,
    IdentitySessionMetadata? Metadata = null)
{
    /// <summary>Asserted only by trusted server code after verification, never from an untrusted request.</summary>
    public IdentitySessionAssurance Assurance { get; init; }
}
