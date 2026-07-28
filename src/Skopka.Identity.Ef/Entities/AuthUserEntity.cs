namespace Skopka.Identity.Ef.Entities;

public sealed class AuthUserEntity
{
    public Guid Id { get; set; }

    public int Flags { get; set; } // UserFlags

    public string? NormalizedUserName { get; set; }
    public string? NormalizedEmail { get; set; }
    public string? NormalizedPhone { get; set; }

    public bool EmailConfirmed { get; set; }
    public bool PhoneConfirmed { get; set; }

    public long Version { get; set; } // optimistic concurrency token
    public string SecurityStamp { get; set; } = null!;

    public DateTimeOffset? DeletedAt { get; set; }
    public DateTimeOffset? BlockedAt { get; set; }
    public DateTimeOffset? BlockedUntil { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ModifiedAt { get; set; }

    // nav
    public UserProfileEntityBase Profile { get; set; } = null!;
    public ICollection<UserExternalLoginEntity> ExternalLogins { get; set; } = new List<UserExternalLoginEntity>();
    public ICollection<UserRoleEntity> RoleMemberships { get; set; } = new List<UserRoleEntity>();
    public UserCredentialEntity? Credential { get; set; }
}
