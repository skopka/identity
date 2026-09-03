using Skopka.Identity.WebAuthn;

namespace Skopka.Identity.Ef.Entities;

public sealed class WebAuthnCredentialEntity
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public byte[] CredentialId { get; set; } = null!;
    public byte[] PublicKey { get; set; } = null!;
    public WebAuthnAlgorithm Algorithm { get; set; }
    public long SignatureCounter { get; set; }
    public Guid AuthenticatorId { get; set; }
    public bool BackedUp { get; set; }
    public string? Label { get; set; }
    public long Version { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? LastUsedAt { get; set; }

    public AuthUserEntity User { get; set; } = null!;
}
