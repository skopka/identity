using Microsoft.Extensions.DependencyInjection.Extensions;
using Skopka.Identity;
using Skopka.Identity.RateLimiting;

namespace Microsoft.Extensions.DependencyInjection;

public static class IdentityRateLimitingBuilderExtensions
{
    public static IdentityBuilder<TProfile> UseHmacRateLimiting<TProfile>(
        this IdentityBuilder<TProfile> builder,
        byte[] partitionKey,
        Action<IdentityRateLimitOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(partitionKey);

        var options = new IdentityRateLimitOptions();
        configure?.Invoke(options);
        ValidateOptions(options);

        var hasher = new HmacRateLimitPartitionHasher(partitionKey);

        builder.Services.RemoveAll<IdentityRateLimitOptions>();
        builder.Services.RemoveAll<IRateLimitPartitionHasher>();
        builder.Services.RemoveAll<IIdentityRateLimiter<TProfile>>();
        builder.Services.AddSingleton(options);
        builder.Services.AddSingleton<IRateLimitPartitionHasher>(hasher);
        builder.Services.AddScoped<
            IIdentityRateLimiter<TProfile>,
            IdentityRateLimiter<TProfile>>();

        return builder;
    }

    private static void ValidateOptions(IdentityRateLimitOptions options)
    {
        ValidatePolicy(
            options.PasswordAccountPermitLimit,
            options.PasswordAccountWindow,
            nameof(options.PasswordAccountPermitLimit));
        ValidatePolicy(
            options.PasswordClientPermitLimit,
            options.PasswordClientWindow,
            nameof(options.PasswordClientPermitLimit));
        ValidatePolicy(
            options.VerificationAccountPermitLimit,
            options.VerificationAccountWindow,
            nameof(options.VerificationAccountPermitLimit));
        ValidatePolicy(
            options.VerificationIntentPermitLimit,
            options.VerificationIntentWindow,
            nameof(options.VerificationIntentPermitLimit));
        ValidatePolicy(
            options.VerificationClientPermitLimit,
            options.VerificationClientWindow,
            nameof(options.VerificationClientPermitLimit));

        if (options.VerificationResendCooldown <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options.VerificationResendCooldown));
        }

        var longestActivePeriod = new[]
        {
            options.PasswordAccountWindow,
            options.PasswordClientWindow,
            options.VerificationAccountWindow,
            options.VerificationIntentWindow,
            options.VerificationClientWindow,
            options.VerificationResendCooldown,
        }.Max();
        if (options.BucketRetention < longestActivePeriod)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options.BucketRetention),
                "Bucket retention must cover every configured active policy period.");
        }

        if (options.CleanupBatchSize <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options.CleanupBatchSize));
        }
    }

    private static void ValidatePolicy(
        int permitLimit,
        TimeSpan window,
        string name)
    {
        if (permitLimit <= 0)
        {
            throw new ArgumentOutOfRangeException(name);
        }

        if (window <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(name);
        }
    }
}
