using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.Sessions;

namespace Skopka.Identity.Ef.Configurations;

internal sealed class RefreshSessionConfiguration
    : IEntityTypeConfiguration<RefreshSessionEntity>
{
    public void Configure(EntityTypeBuilder<RefreshSessionEntity> builder)
    {
        builder.ToTable("identity_refresh_sessions");

        builder.HasKey(session => session.TokenId);

        builder.Property(session => session.TokenId)
            .HasColumnName("token_id");
        builder.Property(session => session.SessionId)
            .HasColumnName("session_id");
        builder.Property(session => session.TokenHash)
            .HasColumnName("token_hash")
            .HasMaxLength(SessionLimits.TokenHashLength)
            .IsRequired();
        builder.Property(session => session.Version)
            .HasColumnName("version")
            .IsConcurrencyToken();
        builder.Property(session => session.CreatedAt)
            .HasColumnName("created_at");
        builder.Property(session => session.ModifiedAt)
            .HasColumnName("modified_at");
        builder.Property(session => session.RotatedAt)
            .HasColumnName("rotated_at");
        builder.Property(session => session.ReplacedByTokenId)
            .HasColumnName("replaced_by_token_id");

        builder.HasIndex(session => session.SessionId)
            .HasDatabaseName("ix_identity_refresh_sessions_session_id");
        builder.HasOne(session => session.Session)
            .WithMany(session => session.RefreshTokens)
            .HasForeignKey(token => token.SessionId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
