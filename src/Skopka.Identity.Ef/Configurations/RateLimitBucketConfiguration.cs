using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.RateLimiting;

namespace Skopka.Identity.Ef.Configurations;

internal sealed class RateLimitBucketConfiguration
    : IEntityTypeConfiguration<RateLimitBucketEntity>
{
    public void Configure(EntityTypeBuilder<RateLimitBucketEntity> builder)
    {
        builder.ToTable("identity_rate_limit_buckets");

        builder.HasKey(bucket => new
        {
            bucket.Scope,
            bucket.PartitionVersion,
            bucket.KeyHash,
        });

        builder.Property(bucket => bucket.Scope)
            .HasColumnName("scope")
            .HasMaxLength(RateLimitLimits.MaximumScopeLength);
        builder.Property(bucket => bucket.PartitionVersion)
            .HasColumnName("partition_version")
            .HasMaxLength(
                RateLimitLimits.MaximumPartitionVersionLength);
        builder.Property(bucket => bucket.KeyHash)
            .HasColumnName("key_hash")
            .HasMaxLength(RateLimitLimits.KeyHashLength);
        builder.Property(bucket => bucket.WindowStartedAt)
            .HasColumnName("window_started_at");
        builder.Property(bucket => bucket.HitCount)
            .HasColumnName("hit_count");
        builder.Property(bucket => bucket.LastHitAt)
            .HasColumnName("last_hit_at");
        builder.Property(bucket => bucket.Version)
            .HasColumnName("version")
            .IsConcurrencyToken();
        builder.Property(bucket => bucket.ModifiedAt)
            .HasColumnName("modified_at");
    }
}
