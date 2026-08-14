using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.Totp;

namespace Skopka.Identity.Ef.Configurations;

internal sealed class TotpFactorConfiguration
    : IEntityTypeConfiguration<TotpFactorEntity>
{
    public void Configure(EntityTypeBuilder<TotpFactorEntity> builder)
    {
        builder.ToTable("user_totp_factors");
        builder.HasKey(factor => factor.UserId);

        builder.Property(factor => factor.UserId).HasColumnName("user_id");
        builder.Property(factor => factor.EnrollmentId)
            .HasColumnName("enrollment_id");
        builder.Property(factor => factor.ProtectedSecret)
            .HasColumnName("protected_secret")
            .HasMaxLength(TotpLimits.MaximumProtectedSecretLength)
            .IsRequired();
        builder.Property(factor => factor.State).HasColumnName("state");
        builder.Property(factor => factor.LastAcceptedCounter)
            .HasColumnName("last_accepted_counter");
        builder.Property(factor => factor.Version)
            .HasColumnName("version")
            .IsConcurrencyToken();
        builder.Property(factor => factor.PendingExpiresAt)
            .HasColumnName("pending_expires_at");
        builder.Property(factor => factor.EnabledAt)
            .HasColumnName("enabled_at");
        builder.Property(factor => factor.CreatedAt)
            .HasColumnName("created_at");
        builder.Property(factor => factor.ModifiedAt)
            .HasColumnName("modified_at");

        builder.HasIndex(factor => factor.EnrollmentId)
            .IsUnique()
            .HasDatabaseName("ux_user_totp_factors_enrollment_id");

        builder.HasOne(factor => factor.User)
            .WithOne()
            .HasForeignKey<TotpFactorEntity>(factor => factor.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}

internal sealed class TotpRecoveryCodeConfiguration
    : IEntityTypeConfiguration<TotpRecoveryCodeEntity>
{
    public void Configure(EntityTypeBuilder<TotpRecoveryCodeEntity> builder)
    {
        builder.ToTable("user_totp_recovery_codes");
        builder.HasKey(code => code.Id);

        builder.Property(code => code.Id).HasColumnName("id");
        builder.Property(code => code.UserId).HasColumnName("user_id");
        builder.Property(code => code.EnrollmentId)
            .HasColumnName("enrollment_id");
        builder.Property(code => code.CodeHash)
            .HasColumnName("code_hash")
            .HasMaxLength(TotpLimits.RecoveryCodeHashLength)
            .IsFixedLength()
            .IsRequired();
        builder.Property(code => code.Version)
            .HasColumnName("version")
            .IsConcurrencyToken();
        builder.Property(code => code.CreatedAt)
            .HasColumnName("created_at");
        builder.Property(code => code.UsedAt).HasColumnName("used_at");

        builder.HasIndex(code => new
        {
            code.UserId,
            code.EnrollmentId,
            code.CodeHash,
        })
            .IsUnique()
            .HasDatabaseName("ux_user_totp_recovery_codes_hash");

        builder.HasOne(code => code.Factor)
            .WithMany(factor => factor.RecoveryCodes)
            .HasForeignKey(code => code.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
