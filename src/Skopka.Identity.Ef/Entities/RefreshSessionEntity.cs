namespace Skopka.Identity.Ef.Entities;

public sealed class RefreshSessionEntity
{
    public Guid TokenId { get; set; }
    public Guid SessionId { get; set; }
    public string TokenHash { get; set; } = null!;
    public long Version { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ModifiedAt { get; set; }
    public DateTimeOffset? RotatedAt { get; set; }
    public Guid? ReplacedByTokenId { get; set; }

    public IdentitySessionEntity Session { get; set; } = null!;
}
