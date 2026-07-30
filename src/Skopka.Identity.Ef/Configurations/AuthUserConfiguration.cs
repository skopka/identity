using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Skopka.Identity.Ef.Entities;

namespace Skopka.Identity.Ef.Configurations;

internal sealed class AuthUserConfiguration : IEntityTypeConfiguration<AuthUserEntity>
{
    public void Configure(EntityTypeBuilder<AuthUserEntity> builder)
    {
        builder.ToTable("auth_users");

        builder.HasKey(user => user.Id);

        builder.Property(user => user.Id).HasColumnName("id");
        builder.Property(user => user.Flags).HasColumnName("flags");
        builder.Property(user => user.NormalizedUserName).HasColumnName("normalized_user_name");
        builder.Property(user => user.NormalizedEmail).HasColumnName("normalized_email");
        builder.Property(user => user.NormalizedPhone).HasColumnName("normalized_phone");
        builder.Property(user => user.EmailConfirmed).HasColumnName("email_confirmed");
        builder.Property(user => user.PhoneConfirmed).HasColumnName("phone_confirmed");
        builder.Property(user => user.Version)
            .HasColumnName("version")
            .IsConcurrencyToken();
        builder.Property(user => user.SecurityStamp)
            .HasColumnName("security_stamp")
            .HasMaxLength(64)
            .IsRequired();
        builder.Property(user => user.DeletedAt).HasColumnName("deleted_at");
        builder.Property(user => user.BlockedAt).HasColumnName("blocked_at");
        builder.Property(user => user.BlockedUntil).HasColumnName("blocked_until");
        builder.Property(user => user.CreatedAt).HasColumnName("created_at");
        builder.Property(user => user.ModifiedAt).HasColumnName("modified_at");

        builder.HasMany(user => user.ExternalLogins)
            .WithOne(login => login.User)
            .HasForeignKey(login => login.UserId)
            .HasConstraintName("fk_user_external_logins_auth_users_user_id")
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasOne(user => user.Credential)
            .WithOne(credential => credential.User)
            .HasForeignKey<UserCredentialEntity>(credential => credential.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
