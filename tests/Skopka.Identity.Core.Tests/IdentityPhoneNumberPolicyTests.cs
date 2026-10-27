using Xunit;
using Skopka.Identity.Errors;
using Skopka.Identity.PhoneOtp;
using Skopka.Identity.RateLimiting;

namespace Skopka.Identity.Core.Tests;

public sealed class IdentityPhoneNumberPolicyTests
{
    [Theory]
    [InlineData("+79990002413", "+79990002413")]
    [InlineData("+7 (999) 000-24-13", "+79990002413")]
    [InlineData("+12125551234", "+12125551234")]
    public void CanonicalizesAllowedNumbers(string input, string expected)
    {
        var result = new IdentityPhoneNumberPolicy(new DefaultIdentityNormalizer(), new PhoneOtpOptions()).Normalize(input);
        Assert.True(result.IsSuccess);
        Assert.Equal(expected, result.Value);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("9990002413")]
    [InlineData("+7 999 abc 2413")]
    [InlineData("+79990002413 ext 5")]
    [InlineData("+712")]
    public void InvalidFormatHasDistinctCode(string? input)
    {
        var result = new IdentityPhoneNumberPolicy(new DefaultIdentityNormalizer(), new PhoneOtpOptions()).Normalize(input);
        Assert.False(result.IsSuccess);
        Assert.Equal(IdentityErrorCodes.PhoneInvalidFormat, Assert.Single(result.Errors).Code);
    }

    [Fact]
    public void CountryRestrictionCarriesAllowedCodes()
    {
        var result = new IdentityPhoneNumberPolicy(new DefaultIdentityNormalizer(), new PhoneOtpOptions { AllowedCountryCodes = ["+7"] }).Normalize("+12125551234");
        var error = Assert.Single(result.Errors);
        Assert.Equal(IdentityErrorCodes.PhoneCountryNotAllowed, error.Code);
        var details = Assert.IsType<ValidationDetails>(error.Details);
        Assert.Equal(["+7"], details.AllowedPhoneCountryCodes);
        Assert.Contains("phone", details.Fields.Keys);
    }

    [Fact]
    public void LegacyConstructorRemainsUsable()
    {
        // These collaborators are unused by construction; this checks the public overload.
        var service = new IdentityPhoneOtpService<object>(new DefaultIdentityNormalizer(),
            null!, null!, null!, Array.Empty<IIdentityRateLimiter<object>>(),
            new IdentityRateLimitOptions(), new PhoneOtpOptions(), null!, null!);
        Assert.NotNull(service);
    }

    [Fact]
    public void PolicyUsesCustomNormalizer()
    {
        var policy = new IdentityPhoneNumberPolicy(new RejectingNormalizer(), new PhoneOtpOptions());
        Assert.Equal(IdentityErrorCodes.PhoneInvalidFormat, Assert.Single(policy.Normalize("+79990002413").Errors).Code);
    }

    private sealed class RejectingNormalizer : IIdentityNormalizer
    {
        public string? NormalizeUserName(string? value) => value;
        public string? NormalizeEmail(string? value) => value;
        public string? NormalizePhone(string? value) => value;
        public string? NormalizePhoneLoginIdentifier(string? value) => null;
    }
}
