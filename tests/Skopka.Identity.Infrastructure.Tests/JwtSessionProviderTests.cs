using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;
using Skopka.Identity.Sessions;
using Skopka.Identity.Users;
using Xunit;

namespace Skopka.Identity.Infrastructure.Tests;

public sealed class JwtSessionProviderTests
{
    [Fact]
    public async Task JwtProviderRoundTripsBoundSessionClaims()
    {
        using var provider = CreateJwtProvider();
        var payload = CreatePayload(
            claims:
            [
                new(IdentitySessionClaimTypes.Name, "alice"),
                new(IdentitySessionClaimTypes.Role, "admin"),
                new(IdentitySessionClaimTypes.Role, "auditor"),
            ]);

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
        Assert.Equal(
            2,
            validated.Claims!.Count(
                claim => claim.Type == IdentitySessionClaimTypes.Role));
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
    public async Task VersionedJwtProviderSignsWithCurrentKeyAndValidatesOverlap()
    {
        var firstKey = CreateSigningKey();
        var secondKey = CreateSigningKey(33);
        using var firstProvider = CreateVersionedJwtProvider(
            "v1",
            new Dictionary<string, byte[]>(StringComparer.Ordinal)
            {
                ["v1"] = firstKey,
            });
        using var rotatedProvider = CreateVersionedJwtProvider(
            "v2",
            new Dictionary<string, byte[]>(StringComparer.Ordinal)
            {
                ["v1"] = firstKey,
                ["v2"] = secondKey,
            });
        using var retiredProvider = CreateVersionedJwtProvider(
            "v2",
            new Dictionary<string, byte[]>(StringComparer.Ordinal)
            {
                ["v2"] = secondKey,
            });

        var firstToken = firstProvider.Generate(CreatePayload());
        var rotatedToken = rotatedProvider.Generate(CreatePayload());

        Assert.Equal(
            "v1",
            new JsonWebTokenHandler()
                .ReadJsonWebToken(firstToken)
                .Kid);
        Assert.Equal(
            "v2",
            new JsonWebTokenHandler()
                .ReadJsonWebToken(rotatedToken)
                .Kid);
        Assert.NotNull(await rotatedProvider.ValidateAsync(
            firstToken,
            CancellationToken.None));
        Assert.NotNull(await rotatedProvider.ValidateAsync(
            rotatedToken,
            CancellationToken.None));
        Assert.Null(await retiredProvider.ValidateAsync(
            firstToken,
            CancellationToken.None));
    }

    [Fact]
    public async Task VersionedJwtProviderAcceptsLegacyTokenWithoutKeyId()
    {
        var firstKey = CreateSigningKey();
        var secondKey = CreateSigningKey(33);
        using var legacyProvider = new HmacJwtAccessTokenProvider(
            firstKey,
            CreateJwtOptions());
        using var secondLegacyProvider = new HmacJwtAccessTokenProvider(
            secondKey,
            CreateJwtOptions());
        using var rotatedProvider = CreateVersionedJwtProvider(
            "v2",
            new Dictionary<string, byte[]>(StringComparer.Ordinal)
            {
                ["v1"] = firstKey,
                ["v2"] = secondKey,
            });

        var legacyToken = legacyProvider.Generate(CreatePayload());
        var secondLegacyToken = secondLegacyProvider.Generate(
            CreatePayload());

        Assert.True(string.IsNullOrEmpty(
            new JsonWebTokenHandler()
                .ReadJsonWebToken(legacyToken)
                .Kid));
        Assert.NotNull(await rotatedProvider.ValidateAsync(
            legacyToken,
            CancellationToken.None));
        Assert.NotNull(await rotatedProvider.ValidateAsync(
            secondLegacyToken,
            CancellationToken.None));
    }

    [Fact]
    public void VersionedJwtProviderRejectsInvalidKeySets()
    {
        var options = CreateJwtOptions();
        var validKey = CreateSigningKey();

        Assert.Throws<ArgumentException>(() =>
            new HmacJwtAccessTokenProvider(
                "missing",
                new Dictionary<string, byte[]>(StringComparer.Ordinal)
                {
                    ["v1"] = validKey,
                },
                options));
        Assert.Throws<ArgumentException>(() =>
            new HmacJwtAccessTokenProvider(
                "bad id",
                new Dictionary<string, byte[]>(StringComparer.Ordinal)
                {
                    ["bad id"] = validKey,
                },
                options));
        Assert.Throws<ArgumentException>(() =>
            new HmacJwtAccessTokenProvider(
                "v1",
                new Dictionary<string, byte[]>(StringComparer.Ordinal)
                {
                    ["v1"] = new byte[31],
                },
                options));
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

    [Fact]
    public void DependencyInjectionDisposesJwtSigningKeyProvider()
    {
        var services = new ServiceCollection();
        services
            .AddSkopkaIdentity<TestProfile>()
            .UseJwtSessions(
                CreateSigningKey(),
                jwt =>
                {
                    jwt.Issuer = "https://issuer.example";
                    jwt.Audience = "identity-api";
                });
        var serviceProvider = services.BuildServiceProvider();
        var tokenProvider = Assert.IsType<HmacJwtAccessTokenProvider>(
            serviceProvider.GetRequiredService<
                IIdentityAccessTokenProvider>());

        serviceProvider.Dispose();

        Assert.Throws<ObjectDisposedException>(() =>
            tokenProvider.Generate(CreatePayload()));
    }

    [Fact]
    public async Task JwtBearerIntegrationBuildsNameAndRolePrincipal()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services
            .AddSkopkaIdentity<TestProfile>()
            .UseJwtSessions(
                CreateSigningKey(),
                jwt =>
                {
                    jwt.Issuer = "https://issuer.example";
                    jwt.Audience = "identity-api";
                    jwt.ClockSkew = TimeSpan.Zero;
                })
            .AddSessionClaimsProvider<TestClaimsProvider>()
            .UseJwtBearerAuthentication();

        using var serviceProvider = services.BuildServiceProvider();
        var tokenProvider = serviceProvider
            .GetRequiredService<IIdentityAccessTokenProvider>();
        var token = tokenProvider.Generate(
            CreatePayload(
                claims:
                [
                    new(IdentitySessionClaimTypes.Name, "alice"),
                    new(IdentitySessionClaimTypes.Role, "admin"),
                    new(IdentitySessionClaimTypes.Role, "auditor"),
                ]));
        using var scope = serviceProvider.CreateScope();
        var httpContext = new DefaultHttpContext
        {
            RequestServices = scope.ServiceProvider,
        };
        httpContext.Request.Headers.Authorization = $"Bearer {token}";

        var result = await httpContext.AuthenticateAsync();
        var bearerOptions = serviceProvider
            .GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        Assert.True(result.Succeeded);
        Assert.Equal("alice", result.Principal!.Identity!.Name);
        Assert.True(result.Principal.IsInRole("admin"));
        Assert.True(result.Principal.IsInRole("auditor"));
        Assert.False(bearerOptions.MapInboundClaims);
        Assert.Equal(
            IdentitySessionClaimTypes.Name,
            bearerOptions.TokenValidationParameters.NameClaimType);
        Assert.Equal(
            IdentitySessionClaimTypes.Role,
            bearerOptions.TokenValidationParameters.RoleClaimType);
        Assert.Contains(
            SecurityAlgorithms.HmacSha256,
            bearerOptions.TokenValidationParameters.ValidAlgorithms);
        Assert.NotNull(
            serviceProvider.GetRequiredService<IAuthorizationService>());
    }

    [Fact]
    public async Task JwtBearerIntegrationAcceptsOverlappingSigningKey()
    {
        var firstKey = CreateSigningKey();
        var services = new ServiceCollection();
        services.AddLogging();
        services
            .AddSkopkaIdentity<TestProfile>()
            .UseJwtSessions(
                "v2",
                new Dictionary<string, byte[]>(StringComparer.Ordinal)
                {
                    ["v1"] = firstKey,
                    ["v2"] = CreateSigningKey(33),
                },
                jwt =>
                {
                    jwt.Issuer = "https://issuer.example";
                    jwt.Audience = "identity-api";
                    jwt.ClockSkew = TimeSpan.Zero;
                })
            .UseJwtBearerAuthentication();
        using var firstProvider = CreateVersionedJwtProvider(
            "v1",
            new Dictionary<string, byte[]>(StringComparer.Ordinal)
            {
                ["v1"] = firstKey,
            });
        using var serviceProvider = services.BuildServiceProvider();
        var token = firstProvider.Generate(CreatePayload());
        using var scope = serviceProvider.CreateScope();
        var httpContext = new DefaultHttpContext
        {
            RequestServices = scope.ServiceProvider,
        };
        httpContext.Request.Headers.Authorization = $"Bearer {token}";

        var result = await httpContext.AuthenticateAsync();

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task JwtBearerOnlineValidationRejectsRevokedSession()
    {
        var services = new ServiceCollection();
        var applicationEventCalled = false;
        services.AddLogging();
        services
            .AddSkopkaIdentity<TestProfile>()
            .UseJwtSessions(
                CreateSigningKey(),
                jwt =>
                {
                    jwt.Issuer = "https://issuer.example";
                    jwt.Audience = "identity-api";
                    jwt.ClockSkew = TimeSpan.Zero;
                })
            .UseJwtBearerAuthentication(
                options => options.ValidateSessionOnEveryRequest = true,
                bearer => bearer.Events.OnTokenValidated = _ =>
                {
                    applicationEventCalled = true;
                    return Task.CompletedTask;
                });
        var sessionService = new RejectingSessionService();
        services.RemoveAll<IIdentitySessionService<TestProfile>>();
        services.AddScoped<IIdentitySessionService<TestProfile>>(
            _ => sessionService);

        using var serviceProvider = services.BuildServiceProvider();
        var token = serviceProvider
            .GetRequiredService<IIdentityAccessTokenProvider>()
            .Generate(CreatePayload());
        using var scope = serviceProvider.CreateScope();
        var httpContext = new DefaultHttpContext
        {
            RequestServices = scope.ServiceProvider,
        };
        httpContext.Request.Headers.Authorization = $"Bearer {token}";

        var result = await httpContext.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.True(applicationEventCalled);
        Assert.True(sessionService.ValidateCalled);
    }

    private static HmacJwtAccessTokenProvider CreateJwtProvider(
        string audience = "identity-api")
        => new(
            CreateSigningKey(),
            CreateJwtOptions(audience));

    private static HmacJwtAccessTokenProvider CreateVersionedJwtProvider(
        string currentKeyId,
        IReadOnlyDictionary<string, byte[]> signingKeys)
        => new(currentKeyId, signingKeys, CreateJwtOptions());

    private static JwtAccessTokenOptions CreateJwtOptions(
        string audience = "identity-api")
        => new()
        {
            Issuer = "https://issuer.example",
            Audience = audience,
            ClockSkew = TimeSpan.Zero,
        };

    private static IdentityAccessTokenPayload CreatePayload(
        DateTimeOffset? issuedAt = null,
        DateTimeOffset? expiresAt = null,
        IReadOnlyList<IdentitySessionClaim>? claims = null)
    {
        var issued = issuedAt ?? DateTimeOffset.UtcNow;
        return new IdentityAccessTokenPayload(
            1,
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            issued,
            expiresAt ?? issued.AddMinutes(5),
            claims);
    }

    private static byte[] CreateSigningKey(int start = 1)
        => Enumerable.Range(start, 32)
            .Select(value => (byte)value)
            .ToArray();

    private sealed class TestClaimsProvider
        : IIdentitySessionClaimsProvider<TestProfile>
    {
        public Task<IReadOnlyCollection<IdentitySessionClaim>>
            GetClaimsAsync(
                IdentityUser<TestProfile> user,
                CancellationToken ct)
            => Task.FromResult<IReadOnlyCollection<IdentitySessionClaim>>(
                [new(IdentitySessionClaimTypes.Role, "custom")]);
    }

    private sealed class RejectingSessionService
        : IIdentitySessionService<TestProfile>
    {
        public bool ValidateCalled { get; private set; }

        public Task<OperationResult<IdentityUser<TestProfile>>>
            ValidateAccessTokenAsync(
                string accessToken,
                CancellationToken ct)
        {
            ValidateCalled = true;
            return Task.FromResult(
                OperationResultFactory.Fail<IdentityUser<TestProfile>>(
                    new Error(
                        IdentityErrorCodes.AccessTokenInvalid,
                        "Invalid.",
                        ErrorType.Unauthorized)));
        }

        public Task<OperationResult<IssuedIdentitySession>> CreateAsync(
            CreateIdentitySessionCommand command,
            CancellationToken ct)
            => throw new NotSupportedException();

        public Task<OperationResult<IssuedIdentitySession>> RefreshAsync(
            RefreshIdentitySessionCommand command,
            CancellationToken ct)
            => throw new NotSupportedException();

        public Task<OperationResult> RevokeAsync(
            RevokeIdentitySessionCommand command,
            CancellationToken ct)
            => throw new NotSupportedException();

        public Task<OperationResult> RevokeByIdAsync(
            RevokeIdentitySessionByIdCommand command,
            CancellationToken ct)
            => throw new NotSupportedException();

        public Task<OperationResult> RevokeAllAsync(
            RevokeAllIdentitySessionsCommand command,
            CancellationToken ct)
            => throw new NotSupportedException();

        public Task<OperationResult<IReadOnlyList<IdentitySessionInfo>>> ListAsync(
            ListIdentitySessionsCommand command,
            CancellationToken ct)
            => throw new NotSupportedException();

        public Task<int> PruneAsync(CancellationToken ct)
            => throw new NotSupportedException();
    }

    public sealed record TestProfile(string DisplayName);
}
