using Skopka.Identity.Authentication;
using Xunit;

namespace Skopka.Identity.Core.Tests;

public sealed class DefaultIdentityNormalizerTests
{
    [Fact]
    public void AutomaticIdentifiersAreOrdinalDistinctAndBounded()
    {
        IIdentityNormalizer normalizer = new VariantNormalizer();

        var identifiers = normalizer.NormalizeAutomaticLoginIdentifiers(
            "+1 (234) 567-8901");

        Assert.Equal(
            ["U:+1 (234) 567-8901", "E:+1 (234) 567-8901", "12345678901"],
            identifiers);
        Assert.Equal(
            IdentityLoginLimits.MaximumAutomaticLoginIdentifiers,
            identifiers.Count);
    }

    [Theory]
    [InlineData("1234-5678", true)]
    [InlineData("+1 (234) 567/8901", false)]
    [InlineData("123.456.7890", true)]
    [InlineData("123+4567890", false)]
    [InlineData("call-12345678", false)]
    [InlineData("1234567", false)]
    [InlineData("1234567890123456", false)]
    public void AutomaticPhoneAliasRequiresPhoneShapedInput(
        string value,
        bool expectedPhoneAlias)
    {
        IIdentityNormalizer normalizer = new DefaultIdentityNormalizer();

        var identifiers = normalizer.NormalizeAutomaticLoginIdentifiers(value);
        var normalizedPhone = normalizer.NormalizePhoneLoginIdentifier(value);

        Assert.Equal(
            expectedPhoneAlias,
            normalizedPhone is not null
                && identifiers.Contains(normalizedPhone)
                && !string.Equals(
                    normalizedPhone,
                    normalizer.NormalizeUserName(value),
                    StringComparison.Ordinal));
    }

    [Fact]
    public void PhoneWithoutDigitsNormalizesToNull()
    {
        var normalizer = new DefaultIdentityNormalizer();

        Assert.Null(normalizer.NormalizePhone("not-a-phone"));
    }

    [Fact]
    public void PhoneLoginIdentifierRejectsLettersEvenWithEnoughDigits()
    {
        IIdentityNormalizer normalizer = new DefaultIdentityNormalizer();

        Assert.Equal("12345678", normalizer.NormalizePhone("call12345678"));
        Assert.Null(
            normalizer.NormalizePhoneLoginIdentifier("call12345678"));
    }

    [Fact]
    public void CustomNormalizerCanOverridePhoneLoginPolicy()
    {
        IIdentityNormalizer normalizer = new CustomPhonePolicyNormalizer();

        Assert.Equal(
            "CUSTOM:local-123",
            normalizer.NormalizePhoneLoginIdentifier("local-123"));
    }

    private sealed class VariantNormalizer : IIdentityNormalizer
    {
        public string? NormalizeUserName(string? value)
            => value is null ? null : $"U:{value}";

        public string? NormalizeEmail(string? value)
            => value is null ? null : $"E:{value}";

        public string? NormalizePhone(string? value)
            => value is null
                ? null
                : new string(value.Where(char.IsDigit).ToArray());

    }

    private sealed class CustomPhonePolicyNormalizer : IIdentityNormalizer
    {
        public string? NormalizeUserName(string? value) => value;
        public string? NormalizeEmail(string? value) => value;
        public string? NormalizePhone(string? value) => value;

        public string? NormalizePhoneLoginIdentifier(string? value)
            => value is null ? null : $"CUSTOM:{value}";
    }
}
