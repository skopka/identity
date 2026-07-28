using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Skopka.Identity.Ef.Entities;

namespace Skopka.Identity.Ef.Configurations;

internal sealed class UserExternalLoginConfiguration : IEntityTypeConfiguration<UserExternalLoginEntity>
{
    public void Configure(EntityTypeBuilder<UserExternalLoginEntity> builder)
    {
        builder.ToTable("user_external_logins");

        builder.HasKey(login => new { login.Provider, login.Subject });

        builder.Property(login => login.UserId).HasColumnName("user_id");
        builder.Property(login => login.Provider).HasColumnName("provider");
        builder.Property(login => login.Subject).HasColumnName("subject");
        builder.Property(login => login.CreatedAt).HasColumnName("created_at");
    }
}
