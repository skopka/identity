using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Skopka.Identity.Verification;
using Xunit;

namespace Skopka.Identity.Infrastructure.Tests;

public sealed class HmacOneTimeCodeProviderTests
{
    [Fact]
    public async Task IssuedCodeVerifiesOnlyForOriginalContext()
    {
        using var keys = CreateKeys("2026-07");
        var provider = new HmacOneTimeCodeProvider(
            keys,
            new HmacOneTimeCodeOptions());
        var context = CreateContext();

        var issued = await provider.IssueAsync(
            context,
            CancellationToken.None);
        var correct = await provider.VerifyAsync(
            context,
            issued.Verifier,
            issued.DeliveryCode!,
            CancellationToken.None);
        var otherBinding = await provider.VerifyAsync(
            context with { Binding = "transfer-43:v1" },
            issued.Verifier,
            issued.DeliveryCode!,
            CancellationToken.None);

        Assert.True(correct);
        Assert.False(otherBinding);
        Assert.Matches("^[0-9]{6}$", issued.DeliveryCode);
        Assert.DoesNotContain(issued.DeliveryCode!, issued.Verifier);
    }

    [Fact]
    public async Task WrongAndMalformedCodesFail()
    {
        using var keys = CreateKeys("2026-07");
        var provider = new HmacOneTimeCodeProvider(
            keys,
            new HmacOneTimeCodeOptions());
        var context = CreateContext();
        var issued = await provider.IssueAsync(
            context,
            CancellationToken.None);

        Assert.False(
            await provider.VerifyAsync(
                context,
                issued.Verifier,
                "00000A",
                CancellationToken.None));
        Assert.False(
            await provider.VerifyAsync(
                context,
                "not-a-verifier",
                issued.DeliveryCode!,
                CancellationToken.None));
    }

    [Fact]
    public async Task HistoricalKeyCanVerifyOutstandingCode()
    {
        var oldKey = RandomNumberGenerator.GetBytes(32);
        var newKey = RandomNumberGenerator.GetBytes(32);
        var context = CreateContext();
        IssuedVerificationMethodChallenge issued;

        using (var oldKeys = new StaticVerificationCodeKeyProvider(
                   "2026-01",
                   oldKey))
        {
            var oldProvider = new HmacOneTimeCodeProvider(
                oldKeys,
                new HmacOneTimeCodeOptions());
            issued = await oldProvider.IssueAsync(
                context,
                CancellationToken.None);
        }

        using var rotatedKeys = new StaticVerificationCodeKeyProvider(
            "2026-07",
            new Dictionary<string, byte[]>
            {
                ["2026-01"] = oldKey,
                ["2026-07"] = newKey,
            });
        var rotatedProvider = new HmacOneTimeCodeProvider(
            rotatedKeys,
            new HmacOneTimeCodeOptions());

        Assert.True(
            await rotatedProvider.VerifyAsync(
                context,
                issued.Verifier,
                issued.DeliveryCode!,
                CancellationToken.None));
    }

    [Fact]
    public void DependencyInjectionRegistersOneTimeCodeProvider()
    {
        var services = new ServiceCollection();
        var key = RandomNumberGenerator.GetBytes(32);

        services
            .AddSkopkaIdentity<TestProfile>()
            .UseHmacOneTimeCodes(
                "2026-07",
                key,
                code => code.Digits = 8,
                verification => verification.MaxAttempts = 3);

        using var serviceProvider = services.BuildServiceProvider();

        Assert.Contains(
            serviceProvider.GetServices<IVerificationMethodProvider>(),
            method => method is HmacOneTimeCodeProvider);
        Assert.Equal(
            8,
            serviceProvider
                .GetRequiredService<HmacOneTimeCodeOptions>()
                .Digits);
        Assert.Equal(
            3,
            serviceProvider
                .GetRequiredService<VerificationOptions>()
                .MaxAttempts);
    }

    private static StaticVerificationCodeKeyProvider CreateKeys(string keyId)
        => new(keyId, RandomNumberGenerator.GetBytes(32));

    private static VerificationMethodContext CreateContext()
        => new(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "payments.confirm",
            "transfer-42:v1");

    public sealed record TestProfile(string DisplayName);
}
