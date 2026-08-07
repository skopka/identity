namespace Skopka.Identity.Ef.Entities;

public sealed class IdentitySessionEntity
{
    public Guid SessionId { get; set; }
    public Guid UserId { get; set; }
    public string SecurityStamp { get; set; } = null!;
    public string? ClientName { get; set; }
    public string? DeviceName { get; set; }
    public long Version { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset LastRefreshedAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }

    public AuthUserEntity User { get; set; } = null!;
    public ICollection<RefreshSessionEntity> RefreshTokens { get; set; } = [];
}
