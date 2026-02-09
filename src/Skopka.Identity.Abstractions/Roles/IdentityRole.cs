namespace Skopka.Identity.Roles;

public class IdentityRole
{
    public Guid Id { get; set; }
    public required string Name { get; init; }
    public string? Description { get; set; }
    public Guid? ParentId { get; set; }
    public IdentityRole? Parent { get; set; }
}
