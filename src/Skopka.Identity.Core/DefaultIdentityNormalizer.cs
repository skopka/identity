namespace Skopka.Identity;

public sealed class DefaultIdentityNormalizer : IIdentityNormalizer
{
    public string? NormalizeUserName(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim().ToUpperInvariant();

    public string? NormalizeEmail(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim().ToUpperInvariant();

    public string? NormalizePhone(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var normalized = new string(value.Where(char.IsDigit).ToArray());
        return normalized.Length == 0 ? null : normalized;
    }
}
