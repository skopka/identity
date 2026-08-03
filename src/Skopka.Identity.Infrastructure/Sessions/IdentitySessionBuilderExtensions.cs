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
        ValidateJwtOptions(jwtOptions);

        var sessionOptions = new IdentitySessionOptions();
        configureSessions?.Invoke(sessionOptions);
        ValidateSessionOptions(sessionOptions);

        var accessTokenProvider = new HmacJwtAccessTokenProvider(
            signingKey,
            jwtOptions);

        return RegisterJwtSessions(
            builder,
            jwtOptions,
            sessionOptions,
            accessTokenProvider);
    }

    public static IdentityBuilder<TProfile> UseJwtSessions<TProfile>(
        this IdentityBuilder<TProfile> builder,
        string currentKeyId,
        IReadOnlyDictionary<string, byte[]> signingKeys,
        Action<JwtAccessTokenOptions> configureJwt,
        Action<IdentitySessionOptions>? configureSessions = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(currentKeyId);
        ArgumentNullException.ThrowIfNull(signingKeys);
        ArgumentNullException.ThrowIfNull(configureJwt);

        var jwtOptions = new JwtAccessTokenOptions();
        configureJwt(jwtOptions);
        ValidateJwtOptions(jwtOptions);

        var sessionOptions = new IdentitySessionOptions();
        configureSessions?.Invoke(sessionOptions);
        ValidateSessionOptions(sessionOptions);

        var accessTokenProvider = new HmacJwtAccessTokenProvider(
            currentKeyId,
            signingKeys,
            jwtOptions);

        return RegisterJwtSessions(
            builder,
            jwtOptions,
            sessionOptions,
            accessTokenProvider);
    }

    private static IdentityBuilder<TProfile> RegisterJwtSessions<TProfile>(
        IdentityBuilder<TProfile> builder,
        JwtAccessTokenOptions jwtOptions,
        IdentitySessionOptions sessionOptions,
        HmacJwtAccessTokenProvider accessTokenProvider)
    {
        var previousProvider = builder.Services
            .LastOrDefault(descriptor => descriptor.ServiceType
                == typeof(HmacJwtAccessTokenProviderRegistration))
            ?.ImplementationInstance as
                HmacJwtAccessTokenProviderRegistration;

        builder.Services.RemoveAll<JwtAccessTokenOptions>();
        builder.Services.RemoveAll<IdentitySessionOptions>();
        builder.Services.RemoveAll<
            HmacJwtAccessTokenProviderRegistration>();
        builder.Services.RemoveAll<IIdentityAccessTokenProvider>();
        builder.Services.RemoveAll<IIdentityRefreshTokenProvider>();
        builder.Services.RemoveAll<IIdentitySessionService<TProfile>>();
        builder.Services.AddSingleton(jwtOptions);
        builder.Services.AddSingleton(sessionOptions);
        builder.Services.AddSingleton(
            new HmacJwtAccessTokenProviderRegistration(
                accessTokenProvider));
        builder.Services.AddSingleton<IIdentityAccessTokenProvider>(
            provider => provider.GetRequiredService<
                HmacJwtAccessTokenProviderRegistration>().Provider);
        builder.Services.AddSingleton<
            IIdentityRefreshTokenProvider,
            OpaqueRefreshTokenProvider>();
        builder.Services.AddScoped<
            IIdentitySessionService<TProfile>,
            IdentitySessionService<TProfile>>();

        previousProvider?.Provider.Dispose();

        return builder;
    }

    private static void ValidateJwtOptions(JwtAccessTokenOptions options)
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
