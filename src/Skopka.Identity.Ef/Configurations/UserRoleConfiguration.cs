using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Skopka.Identity.Ef.Entities;

namespace Skopka.Identity.Ef.Configurations;

internal sealed class UserRoleConfiguration
    : IEntityTypeConfiguration<UserRoleEntity>
{
    public void Configure(EntityTypeBuilder<UserRoleEntity> builder)
    {
        builder.ToTable("identity_user_roles");

        builder.HasKey(membership => new
        {
            membership.UserId,
            membership.RoleId
        })
            .HasName("pk_identity_user_roles");

        builder.Property(membership => membership.UserId)
            .HasColumnName("user_id");
        builder.Property(membership => membership.RoleId)
            .HasColumnName("role_id");
        builder.Property(membership => membership.CreatedAt)
            .HasColumnName("created_at");

        builder.HasOne(membership => membership.User)
            .WithMany(user => user.RoleMemberships)
            .HasForeignKey(membership => membership.UserId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("fk_identity_user_roles_auth_users_user_id");

        builder.HasOne(membership => membership.Role)
            .WithMany(role => role.Memberships)
            .HasForeignKey(membership => membership.RoleId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("fk_identity_user_roles_identity_roles_role_id");

        builder.HasIndex(membership => membership.RoleId)
            .HasDatabaseName("ix_identity_user_roles_role_id");
    }
}
