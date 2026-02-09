namespace Skopka.Identity;

public sealed class DefaultIdentityNormalizer : IIdentityNormalizer
{
    public string? NormalizeUserName(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim().ToUpperInvariant();

    public string? NormalizeEmail(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim().ToUpperInvariant();

    public string? NormalizePhone(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : new string(value.Where(char.IsDigit).ToArray());
}