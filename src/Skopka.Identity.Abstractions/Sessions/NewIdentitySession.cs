namespace Skopka.Identity.Sessions;

public sealed record NewIdentitySession(
    Guid SessionId,
    Guid UserId,
    string SecurityStamp,
    DateTimeOffset ExpiresAt,
    IdentitySessionMetadata? Metadata = null)
{
    /// <summary>Asserted only by trusted server code after verification, never from an untrusted request.</summary>
    public IdentitySessionAssurance Assurance { get; init; }
}
