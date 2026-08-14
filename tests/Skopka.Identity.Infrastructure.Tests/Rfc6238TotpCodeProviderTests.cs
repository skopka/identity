using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Skopka.Identity.Infrastructure.Totp;
using Skopka.Identity.Totp;
using Skopka.Identity.Verification;
using Xunit;

namespace Skopka.Identity.Infrastructure.Tests;

public sealed class Rfc6238TotpCodeProviderTests
{
    private const string RfcSecret =
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    [Theory]
    [InlineData(59L, "287082")]
    [InlineData(1_111_111_109L, "081804")]
    [InlineData(1_111_111_111L, "050471")]
    [InlineData(1_234_567_890L, "005924")]
    [InlineData(2_000_000_000L, "279037")]
    [InlineData(20_000_000_000L, "353130")]
    public void MatchesRfc6238Sha1VectorsAtSixDigits(
        long unixTime,
        string code)
    {
        var provider = new Rfc6238TotpCodeProvider();

        var matched = provider.TryMatchCounter(
            RfcSecret,
            code,
            DateTimeOffset.FromUnixTimeSeconds(unixTime),
            minimumExclusiveCounter: null,
            out _);

        Assert.True(matched);
    }

    [Fact]
    public void AcceptsOneAdjacentTimeStepAndRejectsAcceptedCounterReplay()
    {
        var provider = new Rfc6238TotpCodeProvider();
        var now = DateTimeOffset.FromUnixTimeSeconds(1_111_111_111L);

        var adjacent = provider.TryMatchCounter(
            RfcSecret,
            "081804",
            now,
            minimumExclusiveCounter: null,
            out var acceptedCounter);
        var replay = provider.TryMatchCounter(
            RfcSecret,
            "081804",
            now,
            acceptedCounter,
            out _);

        Assert.True(adjacent);
        Assert.False(replay);
    }

    [Fact]
    public void DataProtectionProtectorRoundTripsAndRejectsTampering()
    {
        var protector = new DataProtectionTotpSecretProtector(
            new EphemeralDataProtectionProvider());
        var protectedSecret = protector.Protect(RfcSecret);

        var restored = protector.TryUnprotect(
            protectedSecret,
            out var secret);
        var tampered = protector.TryUnprotect(
            protectedSecret + "x",
            out _);
        var malformed = protector.TryUnprotect(
            "not-a-protected-value",
            out _);

        Assert.True(restored);
        Assert.Equal(RfcSecret, secret);
        Assert.False(tampered);
        Assert.False(malformed);
        Assert.DoesNotContain(RfcSecret, protectedSecret);
    }

    [Fact]
    public void DependencyInjectionRegistersStandardTotpMethod()
    {
        var services = new ServiceCollection();
        services
            .AddSkopkaIdentity<object>()
            .UseDataProtectionTotp(options =>
                options.RecoveryCodeCount = 8);

        using var provider = services.BuildServiceProvider();

        Assert.Equal(
            8,
            provider.GetRequiredService<TotpOptions>().RecoveryCodeCount);
        Assert.IsType<Rfc6238TotpCodeProvider>(
            provider.GetRequiredService<ITotpCodeProvider>());
        Assert.Contains(
            services,
            descriptor => descriptor.ServiceType
                    == typeof(IVerificationMethodProvider)
                && descriptor.ImplementationType
                    == typeof(TotpVerificationMethodProvider<object>));
    }
}
