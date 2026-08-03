using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Skopka.Identity.Authentication;
using Skopka.Identity.Ef.Entities;

namespace Skopka.Identity.Ef.Configurations;

internal sealed class LoginIdentifierConfiguration
    : IEntityTypeConfiguration<LoginIdentifierEntity>
{
    public void Configure(EntityTypeBuilder<LoginIdentifierEntity> builder)
    {
        builder.ToTable("identity_login_identifiers");

        builder.HasKey(identifier => new
            {
                identifier.UserId,
                identifier.NormalizedKey
            })
            .HasName("pk_identity_login_identifiers");

        builder.Property(identifier => identifier.UserId)
            .HasColumnName("user_id");
        builder.Property(identifier => identifier.NormalizedKey)
            .HasColumnName("normalized_key")
            .HasMaxLength(IdentityLoginLimits.MaximumLoginLength);
        builder.Property(identifier => identifier.IsActive)
            .HasColumnName("is_active");

        builder.HasOne(identifier => identifier.User)
            .WithMany(user => user.LoginIdentifiers)
            .HasForeignKey(identifier => identifier.UserId)
            .HasConstraintName(
                "fk_identity_login_identifiers_auth_users_user_id")
            .OnDelete(DeleteBehavior.Cascade);
    }
}
