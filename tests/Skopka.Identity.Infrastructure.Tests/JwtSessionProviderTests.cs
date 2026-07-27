using Microsoft.Extensions.DependencyInjection;
using Skopka.Identity.Sessions;
using Xunit;

namespace Skopka.Identity.Infrastructure.Tests;

public sealed class JwtSessionProviderTests
{
    [Fact]
    public async Task JwtProviderRoundTripsBoundSessionClaims()
    {
        using var provider = CreateJwtProvider();
        var payload = CreatePayload();

        var token = provider.Generate(payload);
        var validated = await provider.ValidateAsync(
            token,
            CancellationToken.None);

        Assert.NotNull(validated);
        Assert.Equal(payload.FormatVersion, validated.FormatVersion);
        Assert.Equal(payload.TokenId, validated.TokenId);
        Assert.Equal(payload.UserId, validated.UserId);
        Assert.Equal(payload.SessionId, validated.SessionId);
        Assert.Equal(
            payload.IssuedAt.ToUnixTimeSeconds(),
            validated.IssuedAt.ToUnixTimeSeconds());
        Assert.Equal(
            payload.ExpiresAt.ToUnixTimeSeconds(),
            validated.ExpiresAt.ToUnixTimeSeconds());
    }

    [Fact]
    public async Task JwtProviderRejectsTamperingAndWrongAudience()
    {
        using var provider = CreateJwtProvider();
        using var wrongAudience = CreateJwtProvider(audience: "other-api");
        var token = provider.Generate(CreatePayload());
        var replacement = token[^1] == 'A' ? 'B' : 'A';
        var tampered = token[..^1] + replacement;

        var tamperedResult = await provider.ValidateAsync(
            tampered,
            CancellationToken.None);
        var audienceResult = await wrongAudience.ValidateAsync(
            token,
            CancellationToken.None);

        Assert.Null(tamperedResult);
        Assert.Null(audienceResult);
    }

    [Fact]
    public async Task JwtProviderRejectsExpiredToken()
    {
        using var provider = CreateJwtProvider();
        var now = DateTimeOffset.UtcNow.AddMinutes(-10);
        var token = provider.Generate(
            CreatePayload(
                issuedAt: now,
                expiresAt: now.AddMinutes(1)));

        var result = await provider.ValidateAsync(
            token,
            CancellationToken.None);

        Assert.Null(result);
    }

    [Fact]
    public void RefreshProviderGeneratesOpaqueUniqueVerifiableTokens()
    {
        var provider = new OpaqueRefreshTokenProvider();
        var firstId = Guid.NewGuid();
        var secondId = Guid.NewGuid();

        var first = provider.Generate(firstId);
        var second = provider.Generate(secondId);
        var parsed = provider.TryRead(
            first.Token,
            out var parsedId,
            out var parsedHash);

        Assert.True(parsed);
        Assert.Equal(firstId, parsedId);
        Assert.Equal(first.TokenHash, parsedHash);
        Assert.Equal(SessionLimits.TokenHashLength, first.TokenHash.Length);
        Assert.NotEqual(first.Token, second.Token);
        Assert.NotEqual(first.TokenHash, second.TokenHash);
        Assert.DoesNotContain(firstId.ToString("D"), first.Token);
    }

    [Fact]
    public void DependencyInjectionRegistersJwtSessionSubsystem()
    {
        var services = new ServiceCollection();
        var key = Enumerable.Range(1, 32)
            .Select(value => (byte)value)
            .ToArray();

        services
            .AddSkopkaIdentity<TestProfile>()
            .UseJwtSessions(
                key,
                jwt =>
                {
                    jwt.Issuer = "https://issuer.example";
                    jwt.Audience = "identity-api";
                },
                sessions =>
                {
                    sessions.AccessTokenLifetime = TimeSpan.FromMinutes(3);
                });

        using var serviceProvider = services.BuildServiceProvider();

        Assert.IsType<HmacJwtAccessTokenProvider>(
            serviceProvider.GetRequiredService<IIdentityAccessTokenProvider>());
        Assert.IsType<OpaqueRefreshTokenProvider>(
            serviceProvider.GetRequiredService<IIdentityRefreshTokenProvider>());
        Assert.Equal(
            TimeSpan.FromMinutes(3),
            serviceProvider
                .GetRequiredService<IdentitySessionOptions>()
                .AccessTokenLifetime);
        Assert.Contains(
            services,
            descriptor =>
                descriptor.ServiceType
                    == typeof(IIdentitySessionService<TestProfile>)
                && descriptor.ImplementationType
                    == typeof(IdentitySessionService<TestProfile>));
    }

    private static HmacJwtAccessTokenProvider CreateJwtProvider(
        string audience = "identity-api")
        => new(
            Enumerable.Range(1, 32)
                .Select(value => (byte)value)
                .ToArray(),
            new JwtAccessTokenOptions
            {
                Issuer = "https://issuer.example",
                Audience = audience,
                ClockSkew = TimeSpan.Zero,
            });

    private static IdentityAccessTokenPayload CreatePayload(
        DateTimeOffset? issuedAt = null,
        DateTimeOffset? expiresAt = null)
    {
        var issued = issuedAt ?? DateTimeOffset.UtcNow;
        return new IdentityAccessTokenPayload(
            1,
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            issued,
            expiresAt ?? issued.AddMinutes(5));
    }

    public sealed record TestProfile(string DisplayName);
}
