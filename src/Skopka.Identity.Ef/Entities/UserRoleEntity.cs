namespace Skopka.Identity.Ef.Entities;

public sealed class UserRoleEntity
{
    public Guid UserId { get; set; }
    public Guid RoleId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }

    public AuthUserEntity User { get; set; } = null!;
    public RoleEntity Role { get; set; } = null!;
}
