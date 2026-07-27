using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Skopka.Identity.Tokens;
using Xunit;

namespace Skopka.Identity.Infrastructure.Tests;

public sealed class IdentityActionTokenProviderTests
{
    [Fact]
    public void DataProtectionProviderRoundTripsPayload()
    {
        var provider = CreateProvider();
        var payload = CreatePayload(IdentityActionTokenPurpose.EmailConfirmation);

        var token = provider.Generate(payload);
        var success = provider.TryRead(
            token,
            IdentityActionTokenPurpose.EmailConfirmation,
            out var restored);

        Assert.True(success);
        Assert.Equal(payload, restored);
        Assert.DoesNotContain("+", token);
        Assert.DoesNotContain("/", token);
        Assert.DoesNotContain("=", token);
    }

    [Fact]
    public void DataProtectionProviderRejectsTamperedToken()
    {
        var provider = CreateProvider();
        var token = provider.Generate(
            CreatePayload(IdentityActionTokenPurpose.PasswordReset));
        var index = token.Length / 2;
        var replacement = token[index] == 'A' ? 'B' : 'A';
        var tamperedCharacters = token.ToCharArray();
        tamperedCharacters[index] = replacement;
        var tampered = new string(tamperedCharacters);

        var success = provider.TryRead(
            tampered,
            IdentityActionTokenPurpose.PasswordReset,
            out var restored);

        Assert.False(success);
        Assert.Null(restored);
    }

    [Fact]
    public void DataProtectionProviderSeparatesPurposes()
    {
        var provider = CreateProvider();
        var token = provider.Generate(
            CreatePayload(IdentityActionTokenPurpose.EmailConfirmation));

        var success = provider.TryRead(
            token,
            IdentityActionTokenPurpose.PasswordReset,
            out var restored);

        Assert.False(success);
        Assert.Null(restored);
    }

    [Fact]
    public void DependencyInjectionRegistersDataProtectionActionTokens()
    {
        var services = new ServiceCollection();

        services
            .AddSkopkaIdentity<TestProfile>()
            .UseDataProtectionActionTokens(options =>
            {
                options.PasswordResetLifetime = TimeSpan.FromMinutes(15);
            });

        using var serviceProvider = services.BuildServiceProvider();

        Assert.IsType<DataProtectionIdentityActionTokenProvider>(
            serviceProvider.GetRequiredService<IIdentityActionTokenProvider>());
        Assert.Equal(
            TimeSpan.FromMinutes(15),
            serviceProvider
                .GetRequiredService<IdentityActionTokenOptions>()
                .PasswordResetLifetime);
        Assert.Contains(
            services,
            descriptor =>
                descriptor.ServiceType
                    == typeof(IIdentityActionTokenIssuer<TestProfile>)
                && descriptor.ImplementationType
                    == typeof(IdentityActionTokenIssuer<TestProfile>)
                && descriptor.Lifetime == ServiceLifetime.Scoped);
    }

    private static DataProtectionIdentityActionTokenProvider CreateProvider()
        => new(new EphemeralDataProtectionProvider());

    private static IdentityActionTokenPayload CreatePayload(
        IdentityActionTokenPurpose purpose)
        => new(
            1,
            purpose,
            Guid.NewGuid(),
            "SECURITY-STAMP",
            purpose == IdentityActionTokenPurpose.EmailConfirmation
                ? "ALICE@EXAMPLE.COM"
                : null,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddHours(1));

    public sealed record TestProfile(string DisplayName);
}
