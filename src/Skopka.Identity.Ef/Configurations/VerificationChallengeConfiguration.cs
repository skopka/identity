using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.Verification;

namespace Skopka.Identity.Ef.Configurations;

internal sealed class VerificationChallengeConfiguration
    : IEntityTypeConfiguration<VerificationChallengeEntity>
{
    public void Configure(EntityTypeBuilder<VerificationChallengeEntity> builder)
    {
        builder.ToTable("verification_challenges");

        builder.HasKey(challenge => challenge.Id);

        builder.Property(challenge => challenge.Id)
            .HasColumnName("id");
        builder.Property(challenge => challenge.UserId)
            .HasColumnName("user_id");
        builder.Property(challenge => challenge.IntentHash)
            .HasColumnName("intent_hash")
            .HasMaxLength(VerificationIntentHasher.HashLength)
            .IsRequired();
        builder.Property(challenge => challenge.Purpose)
            .HasColumnName("purpose")
            .HasMaxLength(VerificationLimits.MaximumPurposeLength)
            .IsRequired();
        builder.Property(challenge => challenge.Binding)
            .HasColumnName("binding")
            .HasMaxLength(VerificationLimits.MaximumBindingLength)
            .IsRequired();
        builder.Property(challenge => challenge.Method)
            .HasColumnName("method")
            .HasMaxLength(VerificationLimits.MaximumMethodLength)
            .IsRequired();
        builder.Property(challenge => challenge.Verifier)
            .HasColumnName("verifier")
            .HasMaxLength(VerificationLimits.MaximumVerifierLength)
            .IsRequired();
        builder.Property(challenge => challenge.SecurityStamp)
            .HasColumnName("security_stamp")
            .HasMaxLength(64)
            .IsRequired();
        builder.Property(challenge => challenge.FailedAttemptCount)
            .HasColumnName("failed_attempt_count");
        builder.Property(challenge => challenge.MaxAttempts)
            .HasColumnName("max_attempts");
        builder.Property(challenge => challenge.State)
            .HasColumnName("state");
        builder.Property(challenge => challenge.ProofHash)
            .HasColumnName("proof_hash")
            .HasMaxLength(64);
        builder.Property(challenge => challenge.ProofExpiresAt)
            .HasColumnName("proof_expires_at");
        builder.Property(challenge => challenge.Version)
            .HasColumnName("version")
            .IsConcurrencyToken();
        builder.Property(challenge => challenge.ExpiresAt)
            .HasColumnName("expires_at");
        builder.Property(challenge => challenge.CreatedAt)
            .HasColumnName("created_at");
        builder.Property(challenge => challenge.ModifiedAt)
            .HasColumnName("modified_at");
        builder.Property(challenge => challenge.VerifiedAt)
            .HasColumnName("verified_at");
        builder.Property(challenge => challenge.ConsumedAt)
            .HasColumnName("consumed_at");

        builder.HasIndex(challenge => new
        {
            challenge.UserId,
            challenge.State
        })
            .HasDatabaseName("ix_verification_challenges_user_state");

        builder.HasOne(challenge => challenge.User)
            .WithMany()
            .HasForeignKey(challenge => challenge.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
