namespace Skopka.Identity.RateLimiting;

public sealed class IdentityRateLimiter<TProfile>
    : IIdentityRateLimiter<TProfile>
{
    private readonly IRateLimitBucketStore<TProfile> store;
    private readonly IRateLimitPartitionHasher partitionHasher;
    private readonly IdentityRateLimitOptions options;
    private readonly string[] partitionVersions;

    public IdentityRateLimiter(
        IRateLimitBucketStore<TProfile> store,
        IRateLimitPartitionHasher partitionHasher,
        IdentityRateLimitOptions options)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(partitionHasher);
        ArgumentNullException.ThrowIfNull(options);

        this.store = store;
        this.partitionHasher = partitionHasher;
        this.options = options;
        partitionVersions = ValidateAndOrderVersions(partitionHasher);
    }

    public Task<RateLimitDecision> CheckAsync(
        RateLimitRequest request,
        CancellationToken ct)
    {
        Validate(request);
        return store.CheckAsync(
            request.Scope,
            CreatePartitions(request.Scope, request.Key),
            request.PermitLimit,
            request.Window,
            DateTimeOffset.UtcNow,
            ct);
    }

    public Task<RateLimitDecision> HitAsync(
        RateLimitRequest request,
        CancellationToken ct)
    {
        Validate(request);
        return store.HitAsync(
            request.Scope,
            CreatePartitions(request.Scope, request.Key),
            request.PermitLimit,
            request.Window,
            request.MinimumInterval,
            DateTimeOffset.UtcNow,
            ct);
    }

    public Task ResetAsync(
        string scope,
        string key,
        CancellationToken ct)
    {
        ValidatePartition(scope, key);
        return store.ResetAsync(
            scope,
            CreatePartitions(scope, key),
            ct);
    }

    public Task<int> PruneAsync(CancellationToken ct)
    {
        if (options.BucketRetention <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options.BucketRetention));
        }

        if (options.CleanupBatchSize <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options.CleanupBatchSize));
        }

        return store.PruneAsync(
            DateTimeOffset.UtcNow.Subtract(options.BucketRetention),
            options.CleanupBatchSize,
            ct);
    }

    private static void Validate(RateLimitRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidatePartition(request.Scope, request.Key);

        if (request.PermitLimit <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(request.PermitLimit));
        }

        if (request.Window <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(request.Window));
        }

        if (request.MinimumInterval <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(request.MinimumInterval));
        }
    }

    private static void ValidatePartition(string scope, string key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scope);
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        if (scope.Length > RateLimitLimits.MaximumScopeLength)
        {
            throw new ArgumentException(
                "Rate-limit scope exceeds the supported length.",
                nameof(scope));
        }

        if (key.Length > RateLimitLimits.MaximumKeyLength)
        {
            throw new ArgumentException(
                "Rate-limit key exceeds the supported length.",
                nameof(key));
        }
    }

    private IReadOnlyList<RateLimitPartition> CreatePartitions(
        string scope,
        string key)
    {
        var partitions = new RateLimitPartition[
            partitionVersions.Length];
        for (var index = 0; index < partitionVersions.Length; index++)
        {
            var version = partitionVersions[index];
            var keyHash = partitionHasher.Hash(
                version,
                scope,
                key);
            if (string.IsNullOrWhiteSpace(keyHash)
                || keyHash.Length > RateLimitLimits.KeyHashLength)
            {
                throw new InvalidOperationException(
                    "The rate-limit partition hasher returned an invalid key hash.");
            }

            partitions[index] = new RateLimitPartition(
                version,
                keyHash);
        }

        return partitions;
    }

    private static string[] ValidateAndOrderVersions(
        IRateLimitPartitionHasher partitionHasher)
    {
        var currentVersion = partitionHasher.CurrentVersion;
        ValidateVersion(currentVersion);

        var versions = partitionHasher.Versions
            ?? throw new InvalidOperationException(
                "The rate-limit partition hasher returned no versions.");
        if (versions.Count is < 1
            or > RateLimitLimits.MaximumPartitionVersions)
        {
            throw new InvalidOperationException(
                $"The rate-limit partition hasher must expose between 1 and {RateLimitLimits.MaximumPartitionVersions} versions.");
        }

        var distinct = new HashSet<string>(StringComparer.Ordinal);
        foreach (var version in versions)
        {
            ValidateVersion(version);
            if (!distinct.Add(version))
            {
                throw new InvalidOperationException(
                    "The rate-limit partition hasher exposed duplicate versions.");
            }
        }

        if (!distinct.Contains(currentVersion))
        {
            throw new InvalidOperationException(
                "The current rate-limit partition version is not exposed by the hasher.");
        }

        return
        [
            currentVersion,
            .. distinct
                .Where(version => !string.Equals(
                    version,
                    currentVersion,
                    StringComparison.Ordinal))
                .Order(StringComparer.Ordinal),
        ];
    }

    private static void ValidateVersion(string? version)
    {
        if (string.IsNullOrWhiteSpace(version)
            || version.Length
                > RateLimitLimits.MaximumPartitionVersionLength
            || version.Any(character =>
                !IsAsciiLetterOrDigit(character)
                && character is not '.' and not '_' and not '-'))
        {
            throw new InvalidOperationException(
                "Rate-limit partition versions must contain only ASCII letters, digits, '.', '_' or '-'.");
        }
    }

    private static bool IsAsciiLetterOrDigit(char value)
        => value is >= 'a' and <= 'z'
            or >= 'A' and <= 'Z'
            or >= '0' and <= '9';
}
