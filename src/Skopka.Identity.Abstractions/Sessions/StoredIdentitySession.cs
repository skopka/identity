namespace Skopka.Identity.Sessions;

public sealed record StoredIdentitySession(
    Guid SessionId,
    Guid UserId,
    string SecurityStamp,
    long Version,
    DateTimeOffset ExpiresAt,
    DateTimeOffset CreatedAt,
    DateTimeOffset LastRefreshedAt,
    DateTimeOffset? RevokedAt,
    IdentitySessionMetadata? Metadata = null)
{
    /// <summary>Asserted only by trusted server code after verification, never from an untrusted request.</summary>
    public IdentitySessionAssurance Assurance { get; init; }

    /// <summary>Trusted security context, or null for legacy sessions.</summary>
    public IdentitySessionContext? Context { get; init; }
}
