namespace Skopka.Identity.Ef.Entities;

public sealed class UserExternalLoginEntity
{
    public Guid UserId { get; set; }
    public string Provider { get; set; } = null!;
    public string Subject { get; set; } = null!;
    public DateTimeOffset CreatedAt { get; set; }

    public AuthUserEntity User { get; set; } = null!;
}