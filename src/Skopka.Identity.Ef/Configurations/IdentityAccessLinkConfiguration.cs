using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.Sessions;
using Skopka.Identity.Totp;

namespace Skopka.Identity.Ef.Configurations;

internal sealed class IdentityAccessLinkConfiguration : IEntityTypeConfiguration<IdentityAccessLinkEntity>
{
    public void Configure(EntityTypeBuilder<IdentityAccessLinkEntity> b)
    {
        b.ToTable("identity_access_links");
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasColumnName("id");
        b.Property(x => x.UserId).HasColumnName("user_id");
        b.Property(x => x.UserVersion).HasColumnName("user_version");
        b.Property(x => x.Scope).HasColumnName("scope").HasMaxLength(IdentitySessionContext.MaximumValueLength).IsRequired();
        b.Property(x => x.TokenHash).HasColumnName("token_hash").HasMaxLength(64).IsRequired();
        b.Property(x => x.ExpiresAt).HasColumnName("expires_at");
        b.Property(x => x.Version).HasColumnName("version").IsConcurrencyToken();
        b.Property(x => x.EnrollmentId).HasColumnName("enrollment_id");
        b.Property(x => x.ProtectedSecret).HasColumnName("protected_secret").HasMaxLength(TotpLimits.MaximumProtectedSecretLength);
        b.Property(x => x.EnrollmentExpiresAt).HasColumnName("enrollment_expires_at");
        b.Property(x => x.FailedAttempts).HasColumnName("failed_attempts");
        b.Property(x => x.Consumed).HasColumnName("consumed");
        b.HasIndex(x => x.UserId).HasDatabaseName("ix_identity_access_links_user_id");
        b.HasIndex(x => x.ExpiresAt).HasDatabaseName("ix_identity_access_links_expires_at");
        b.HasOne<AuthUserEntity>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
    }
}
