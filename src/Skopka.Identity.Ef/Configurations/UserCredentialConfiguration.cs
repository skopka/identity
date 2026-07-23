using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Skopka.Identity.Ef.Entities;

namespace Skopka.Identity.Ef.Configurations;

internal sealed class UserCredentialConfiguration : IEntityTypeConfiguration<UserCredentialEntity>
{
    public void Configure(EntityTypeBuilder<UserCredentialEntity> builder)
    {
        builder.ToTable("user_credentials");

        builder.HasKey(credential => credential.UserId);

        builder.Property(credential => credential.UserId).HasColumnName("user_id");
        builder.Property(credential => credential.PasswordVerifier).HasColumnName("password_verifier");
        builder.Property(credential => credential.UpdatedAt).HasColumnName("updated_at");
    }
}
