using Microsoft.Extensions.DependencyInjection.Extensions;
using Skopka.Identity;
using Skopka.Identity.Sessions;

namespace Microsoft.Extensions.DependencyInjection;

public static class IdentitySessionBuilderExtensions
{
    public static IdentityBuilder<TProfile> UseJwtSessions<TProfile>(
        this IdentityBuilder<TProfile> builder,
        byte[] signingKey,
        Action<JwtAccessTokenOptions> configureJwt,
        Action<IdentitySessionOptions>? configureSessions = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(signingKey);
        ArgumentNullException.ThrowIfNull(configureJwt);

        var jwtOptions = new JwtAccessTokenOptions();
        configureJwt(jwtOptions);
        ValidateJwtOptions(jwtOptions, signingKey);

        var sessionOptions = new IdentitySessionOptions();
        configureSessions?.Invoke(sessionOptions);
        ValidateSessionOptions(sessionOptions);

        var accessTokenProvider = new HmacJwtAccessTokenProvider(
            signingKey,
            jwtOptions);

        builder.Services.RemoveAll<JwtAccessTokenOptions>();
        builder.Services.RemoveAll<IdentitySessionOptions>();
        builder.Services.RemoveAll<IIdentityAccessTokenProvider>();
        builder.Services.RemoveAll<IIdentityRefreshTokenProvider>();
        builder.Services.RemoveAll<IIdentitySessionService<TProfile>>();
        builder.Services.AddSingleton(jwtOptions);
        builder.Services.AddSingleton(sessionOptions);
        builder.Services.AddSingleton<IIdentityAccessTokenProvider>(
            accessTokenProvider);
        builder.Services.AddSingleton<
            IIdentityRefreshTokenProvider,
            OpaqueRefreshTokenProvider>();
        builder.Services.AddScoped<
            IIdentitySessionService<TProfile>,
            IdentitySessionService<TProfile>>();

        return builder;
    }

    private static void ValidateJwtOptions(
        JwtAccessTokenOptions options,
        byte[] signingKey)
    {
        if (string.IsNullOrWhiteSpace(options.Issuer))
        {
            throw new ArgumentException("JWT issuer is required.");
        }

        if (string.IsNullOrWhiteSpace(options.Audience))
        {
            throw new ArgumentException("JWT audience is required.");
        }

        if (options.ClockSkew < TimeSpan.Zero
            || options.ClockSkew > TimeSpan.FromMinutes(5))
        {
            throw new ArgumentOutOfRangeException(
                nameof(options.ClockSkew),
                "JWT clock skew must be between zero and five minutes.");
        }

        if (signingKey.Length < 32)
        {
            throw new ArgumentException(
                "The JWT signing key must contain at least 32 bytes.",
                nameof(signingKey));
        }
    }

    private static void ValidateSessionOptions(
        IdentitySessionOptions options)
    {
        if (options.AccessTokenLifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options.AccessTokenLifetime));
        }

        if (options.RefreshSessionLifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options.RefreshSessionLifetime));
        }

        if (options.RetentionAfterExpiration < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options.RetentionAfterExpiration));
        }

        if (options.CleanupBatchSize <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options.CleanupBatchSize));
        }
    }
}
