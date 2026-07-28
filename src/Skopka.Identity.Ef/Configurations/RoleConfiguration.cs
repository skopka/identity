using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.Roles;

namespace Skopka.Identity.Ef.Configurations;

internal sealed class RoleConfiguration : IEntityTypeConfiguration<RoleEntity>
{
    public void Configure(EntityTypeBuilder<RoleEntity> builder)
    {
        builder.ToTable("identity_roles");

        builder.HasKey(role => role.Id)
            .HasName("pk_identity_roles");

        builder.Property(role => role.Id).HasColumnName("id");
        builder.Property(role => role.Name)
            .HasColumnName("name")
            .HasMaxLength(IdentityRoleLimits.MaximumNameLength)
            .IsRequired();
        builder.Property(role => role.NormalizedName)
            .HasColumnName("normalized_name")
            .HasMaxLength(IdentityRoleLimits.MaximumNameLength)
            .IsRequired();
        builder.Property(role => role.Description)
            .HasColumnName("description")
            .HasMaxLength(IdentityRoleLimits.MaximumDescriptionLength);
        builder.Property(role => role.ParentId).HasColumnName("parent_id");
        builder.Property(role => role.Version)
            .HasColumnName("version")
            .IsConcurrencyToken();
        builder.Property(role => role.CreatedAt).HasColumnName("created_at");
        builder.Property(role => role.ModifiedAt).HasColumnName("modified_at");

        builder.HasIndex(role => role.NormalizedName)
            .IsUnique()
            .HasDatabaseName("ux_identity_roles_normalized_name");
        builder.HasIndex(role => role.ParentId)
            .HasDatabaseName("ix_identity_roles_parent_id");

        builder.HasOne(role => role.Parent)
            .WithMany(role => role.Children)
            .HasForeignKey(role => role.ParentId)
            .OnDelete(DeleteBehavior.SetNull)
            .HasConstraintName("fk_identity_roles_identity_roles_parent_id");
    }
}
