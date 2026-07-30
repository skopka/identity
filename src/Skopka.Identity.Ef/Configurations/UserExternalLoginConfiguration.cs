using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.ExternalLogins;

namespace Skopka.Identity.Ef.Configurations;

internal sealed class UserExternalLoginConfiguration : IEntityTypeConfiguration<UserExternalLoginEntity>
{
    public void Configure(EntityTypeBuilder<UserExternalLoginEntity> builder)
    {
        builder.ToTable("user_external_logins");

        builder.HasKey(login => new { login.Provider, login.Subject })
            .HasName("pk_user_external_logins");

        builder.Property(login => login.UserId).HasColumnName("user_id");
        builder.Property(login => login.Provider)
            .HasColumnName("provider")
            .HasMaxLength(ExternalLoginLimits.MaximumProviderLength);
        builder.Property(login => login.Subject)
            .HasColumnName("subject")
            .HasMaxLength(ExternalLoginLimits.MaximumSubjectLength);
        builder.Property(login => login.CreatedAt).HasColumnName("created_at");

        builder.HasIndex(login => login.UserId)
            .HasDatabaseName("ix_user_external_logins_user_id");
    }
}
