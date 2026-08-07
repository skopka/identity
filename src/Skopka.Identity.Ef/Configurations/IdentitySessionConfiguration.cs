using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.Sessions;

namespace Skopka.Identity.Ef.Configurations;

internal sealed class IdentitySessionConfiguration
    : IEntityTypeConfiguration<IdentitySessionEntity>
{
    public void Configure(EntityTypeBuilder<IdentitySessionEntity> builder)
    {
        builder.ToTable("identity_sessions");

        builder.HasKey(session => session.SessionId);

        builder.Property(session => session.SessionId)
            .HasColumnName("session_id");
        builder.Property(session => session.UserId)
            .HasColumnName("user_id");
        builder.Property(session => session.SecurityStamp)
            .HasColumnName("security_stamp")
            .HasMaxLength(SessionLimits.SecurityStampLength)
            .IsRequired();
        builder.Property(session => session.ClientName)
            .HasColumnName("client_name")
            .HasMaxLength(SessionLimits.MaximumClientNameLength);
        builder.Property(session => session.DeviceName)
            .HasColumnName("device_name")
            .HasMaxLength(SessionLimits.MaximumDeviceNameLength);
        builder.Property(session => session.Version)
            .HasColumnName("version")
            .IsConcurrencyToken();
        builder.Property(session => session.ExpiresAt)
            .HasColumnName("expires_at");
        builder.Property(session => session.CreatedAt)
            .HasColumnName("created_at");
        builder.Property(session => session.LastRefreshedAt)
            .HasColumnName("last_refreshed_at");
        builder.Property(session => session.RevokedAt)
            .HasColumnName("revoked_at");

        builder.HasIndex(session => session.UserId)
            .HasDatabaseName("ix_identity_sessions_user_id");
        builder.HasIndex(session => session.ExpiresAt)
            .HasDatabaseName("ix_identity_sessions_expires_at");

        builder.HasOne(session => session.User)
            .WithMany()
            .HasForeignKey(session => session.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
