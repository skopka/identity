using Microsoft.EntityFrameworkCore;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.RateLimiting;

namespace Skopka.Identity.Ef;

public sealed class EfRateLimitBucketStore<TProfile>(
    IdentityDbContext<TProfile> dbContext)
    : IRateLimitBucketStore<TProfile>
{
    private const int MaximumConcurrencyRetries = 3;

    public async Task<RateLimitDecision> CheckAsync(
        string scope,
        IReadOnlyList<RateLimitPartition> partitions,
        int permitLimit,
        TimeSpan window,
        DateTimeOffset now,
        CancellationToken ct)
    {
        ValidatePartitions(partitions);
        var buckets = await Query(scope, partitions)
            .AsNoTracking()
            .ToListAsync(ct);
        var denied = FilterExact(buckets, partitions)
            .Where(bucket => !IsWindowExpired(
                bucket,
                window,
                now))
            .Where(bucket => bucket.HitCount >= permitLimit)
            .Select(bucket => bucket.WindowStartedAt.Add(window))
            .DefaultIfEmpty()
            .Max();
        if (denied == default)
        {
            return Allowed();
        }

        return Denied(denied);
    }

    public async Task<RateLimitDecision> HitAsync(
        string scope,
        IReadOnlyList<RateLimitPartition> partitions,
        int permitLimit,
        TimeSpan window,
        TimeSpan? minimumInterval,
        DateTimeOffset now,
        CancellationToken ct)
    {
        ValidatePartitions(partitions);
        for (var attempt = 0; attempt < MaximumConcurrencyRetries; attempt++)
        {
            var loaded = await Query(scope, partitions)
                .ToListAsync(ct);
            var buckets = FilterExact(
                    loaded,
                    partitions)
                .ToList();
            var active = buckets
                .Where(bucket => !IsWindowExpired(
                    bucket,
                    window,
                    now))
                .ToList();

            var limitRetryAfter = active
                .Where(bucket => bucket.HitCount >= permitLimit)
                .Select(bucket =>
                    bucket.WindowStartedAt.Add(window))
                .DefaultIfEmpty()
                .Max();
            if (limitRetryAfter != default)
            {
                Detach(loaded);
                return Denied(limitRetryAfter);
            }

            if (minimumInterval is not null
                && active.Count > 0)
            {
                var cooldownRetryAfter = active.Max(
                    bucket => bucket.LastHitAt.Add(
                        minimumInterval.Value));
                if (cooldownRetryAfter > now)
                {
                    Detach(loaded);
                    return Denied(cooldownRetryAfter);
                }
            }

            var windowStartedAt = active.Count == 0
                ? now
                : active.Max(bucket => bucket.WindowStartedAt);
            var nextHitCount = checked(
                (active.Count == 0
                    ? 0
                    : active.Max(bucket => bucket.HitCount))
                + 1);
            var byPartition = buckets.ToDictionary(
                bucket => (
                    bucket.PartitionVersion,
                    bucket.KeyHash));
            var added = false;

            foreach (var partition in partitions)
            {
                if (!byPartition.TryGetValue(
                        (partition.Version, partition.KeyHash),
                        out var bucket))
                {
                    bucket = new RateLimitBucketEntity
                    {
                        Scope = scope,
                        PartitionVersion = partition.Version,
                        KeyHash = partition.KeyHash,
                        Version = 1,
                    };
                    dbContext.RateLimitBuckets.Add(bucket);
                    buckets.Add(bucket);
                    added = true;
                }
                else
                {
                    bucket.Version = checked(bucket.Version + 1);
                }

                bucket.WindowStartedAt = windowStartedAt;
                bucket.HitCount = nextHitCount;
                bucket.LastHitAt = now;
                bucket.ModifiedAt = now;
            }

            try
            {
                await dbContext.SaveChangesAsync(ct);
                return Allowed();
            }
            catch (DbUpdateConcurrencyException) when (
                attempt + 1 < MaximumConcurrencyRetries)
            {
                Detach(loaded);
                Detach(buckets);
            }
            catch (DbUpdateException) when (
                added
                && attempt + 1 < MaximumConcurrencyRetries)
            {
                Detach(loaded);
                Detach(buckets);
            }
        }

        throw new InvalidOperationException(
            "Could not update the rate-limit bucket due to concurrent changes.");
    }

    public async Task ResetAsync(
        string scope,
        IReadOnlyList<RateLimitPartition> partitions,
        CancellationToken ct)
    {
        ValidatePartitions(partitions);
        for (var attempt = 0; attempt < MaximumConcurrencyRetries; attempt++)
        {
            var loaded = await Query(scope, partitions)
                .ToListAsync(ct);
            var buckets = FilterExact(
                    loaded,
                    partitions)
                .ToList();
            if (buckets.Count == 0)
            {
                Detach(loaded);
                return;
            }

            dbContext.RateLimitBuckets.RemoveRange(buckets);

            try
            {
                await dbContext.SaveChangesAsync(ct);
                return;
            }
            catch (DbUpdateConcurrencyException) when (
                attempt + 1 < MaximumConcurrencyRetries)
            {
                Detach(loaded);
            }
        }

        throw new InvalidOperationException(
            "Could not reset the rate-limit bucket due to concurrent changes.");
    }

    public async Task<int> PruneAsync(
        DateTimeOffset modifiedBefore,
        int maxCount,
        CancellationToken ct)
    {
        if (maxCount <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxCount));
        }

        for (var attempt = 0; attempt < MaximumConcurrencyRetries; attempt++)
        {
            var buckets = await dbContext.RateLimitBuckets
                .Where(bucket => bucket.ModifiedAt < modifiedBefore)
                .OrderBy(bucket => bucket.ModifiedAt)
                .Take(maxCount)
                .ToListAsync(ct);
            if (buckets.Count == 0)
            {
                return 0;
            }

            dbContext.RateLimitBuckets.RemoveRange(buckets);

            try
            {
                await dbContext.SaveChangesAsync(ct);
                return buckets.Count;
            }
            catch (DbUpdateConcurrencyException) when (
                attempt + 1 < MaximumConcurrencyRetries)
            {
                foreach (var bucket in buckets)
                {
                    dbContext.Entry(bucket).State =
                        EntityState.Detached;
                }
            }
        }

        throw new InvalidOperationException(
            "Could not prune rate-limit buckets due to concurrent changes.");
    }

    private static bool IsWindowExpired(
        RateLimitBucketEntity bucket,
        TimeSpan window,
        DateTimeOffset now)
        => bucket.WindowStartedAt.Add(window) <= now;

    private static RateLimitDecision Allowed() => new(true, null);

    private static RateLimitDecision Denied(DateTimeOffset retryAfter)
        => new(false, retryAfter);

    private IQueryable<RateLimitBucketEntity> Query(
        string scope,
        IReadOnlyList<RateLimitPartition> partitions)
    {
        var versions = partitions
            .Select(partition => partition.Version)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        var hashes = partitions
            .Select(partition => partition.KeyHash)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        return dbContext.RateLimitBuckets.Where(
            bucket => bucket.Scope == scope
                && versions.Contains(bucket.PartitionVersion)
                && hashes.Contains(bucket.KeyHash));
    }

    private static IEnumerable<RateLimitBucketEntity> FilterExact(
        IEnumerable<RateLimitBucketEntity> buckets,
        IReadOnlyList<RateLimitPartition> partitions)
    {
        var keys = partitions
            .Select(partition => (
                partition.Version,
                partition.KeyHash))
            .ToHashSet();
        return buckets.Where(bucket => keys.Contains(
            (bucket.PartitionVersion, bucket.KeyHash)));
    }

    private static void ValidatePartitions(
        IReadOnlyList<RateLimitPartition> partitions)
    {
        ArgumentNullException.ThrowIfNull(partitions);
        if (partitions.Count == 0)
        {
            throw new ArgumentException(
                "At least one rate-limit partition is required.",
                nameof(partitions));
        }

        if (partitions.Count
            > RateLimitLimits.MaximumPartitionVersions)
        {
            throw new ArgumentException(
                $"At most {RateLimitLimits.MaximumPartitionVersions} rate-limit partitions are supported.",
                nameof(partitions));
        }

        var unique = new HashSet<(string Version, string KeyHash)>();
        foreach (var partition in partitions)
        {
            ArgumentNullException.ThrowIfNull(partition);
            if (string.IsNullOrWhiteSpace(partition.Version)
                || partition.Version.Length
                    > RateLimitLimits.MaximumPartitionVersionLength)
            {
                throw new ArgumentException(
                    "A rate-limit partition has an invalid version.",
                    nameof(partitions));
            }

            if (string.IsNullOrWhiteSpace(partition.KeyHash)
                || partition.KeyHash.Length
                    > RateLimitLimits.KeyHashLength)
            {
                throw new ArgumentException(
                    "A rate-limit partition has an invalid key hash.",
                    nameof(partitions));
            }

            if (!unique.Add((
                    partition.Version,
                    partition.KeyHash)))
            {
                throw new ArgumentException(
                    "Duplicate rate-limit partitions are not supported.",
                    nameof(partitions));
            }
        }
    }

    private void Detach(
        IEnumerable<RateLimitBucketEntity> buckets)
    {
        foreach (var bucket in buckets)
        {
            dbContext.Entry(bucket).State = EntityState.Detached;
        }
    }
}
