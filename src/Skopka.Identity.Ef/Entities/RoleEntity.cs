namespace Skopka.Identity.Ef.Entities;

public sealed class RoleEntity
{
    public Guid Id { get; set; }
    public string Name { get; set; } = null!;
    public string NormalizedName { get; set; } = null!;
    public string? Description { get; set; }
    public Guid? ParentId { get; set; }
    public long Version { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ModifiedAt { get; set; }

    public RoleEntity? Parent { get; set; }
    public ICollection<RoleEntity> Children { get; set; } = new List<RoleEntity>();
    public ICollection<UserRoleEntity> Memberships { get; set; } =
        new List<UserRoleEntity>();
}
