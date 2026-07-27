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
        string keyHash,
        int permitLimit,
        TimeSpan window,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var bucket = await dbContext.RateLimitBuckets
            .AsNoTracking()
            .SingleOrDefaultAsync(
                entity => entity.Scope == scope
                    && entity.KeyHash == keyHash,
                ct);

        if (bucket is null || IsWindowExpired(bucket, window, now))
        {
            return Allowed();
        }

        return bucket.HitCount >= permitLimit
            ? Denied(bucket.WindowStartedAt.Add(window))
            : Allowed();
    }

    public async Task<RateLimitDecision> HitAsync(
        string scope,
        string keyHash,
        int permitLimit,
        TimeSpan window,
        TimeSpan? minimumInterval,
        DateTimeOffset now,
        CancellationToken ct)
    {
        for (var attempt = 0; attempt < MaximumConcurrencyRetries; attempt++)
        {
            var bucket = await dbContext.RateLimitBuckets
                .SingleOrDefaultAsync(
                    entity => entity.Scope == scope
                        && entity.KeyHash == keyHash,
                    ct);

            if (bucket is null)
            {
                bucket = new RateLimitBucketEntity
                {
                    Scope = scope,
                    KeyHash = keyHash,
                    WindowStartedAt = now,
                    HitCount = 1,
                    LastHitAt = now,
                    Version = 1,
                    ModifiedAt = now,
                };
                dbContext.RateLimitBuckets.Add(bucket);
            }
            else
            {
                var windowExpired = IsWindowExpired(bucket, window, now);
                var currentHitCount = windowExpired ? 0 : bucket.HitCount;
                var windowStartedAt = windowExpired
                    ? now
                    : bucket.WindowStartedAt;

                if (currentHitCount >= permitLimit)
                {
                    return Denied(windowStartedAt.Add(window));
                }

                if (minimumInterval is not null)
                {
                    var nextAllowedAt = bucket.LastHitAt.Add(
                        minimumInterval.Value);
                    if (nextAllowedAt > now)
                    {
                        return Denied(nextAllowedAt);
                    }
                }

                bucket.WindowStartedAt = windowStartedAt;
                bucket.HitCount = checked(currentHitCount + 1);
                bucket.LastHitAt = now;
                bucket.Version = checked(bucket.Version + 1);
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
                Detach(bucket);
            }
            catch (DbUpdateException) when (
                bucket.Version == 1
                && attempt + 1 < MaximumConcurrencyRetries)
            {
                Detach(bucket);
            }
        }

        throw new InvalidOperationException(
            "Could not update the rate-limit bucket due to concurrent changes.");
    }

    public async Task ResetAsync(
        string scope,
        string keyHash,
        CancellationToken ct)
    {
        for (var attempt = 0; attempt < MaximumConcurrencyRetries; attempt++)
        {
            var bucket = await dbContext.RateLimitBuckets
                .SingleOrDefaultAsync(
                    entity => entity.Scope == scope
                        && entity.KeyHash == keyHash,
                    ct);
            if (bucket is null)
            {
                return;
            }

            dbContext.RateLimitBuckets.Remove(bucket);

            try
            {
                await dbContext.SaveChangesAsync(ct);
                return;
            }
            catch (DbUpdateConcurrencyException) when (
                attempt + 1 < MaximumConcurrencyRetries)
            {
                Detach(bucket);
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
                    Detach(bucket);
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

    private void Detach(object entity)
        => dbContext.Entry(entity).State = EntityState.Detached;
}
