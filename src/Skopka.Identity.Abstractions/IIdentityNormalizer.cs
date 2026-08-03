namespace Skopka.Identity;

public interface IIdentityNormalizer
{
    string? NormalizeUserName(string? value);
    string? NormalizeEmail(string? value);
    string? NormalizePhone(string? value);

    string? NormalizePhoneLoginIdentifier(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.Length
                > Authentication.IdentityLoginLimits.MaximumLoginLength
            || !IsPhoneShaped(value))
        {
            return null;
        }

        var normalized = NormalizePhone(value);
        return string.IsNullOrEmpty(normalized)
            || normalized.Length
                > Authentication.IdentityLoginLimits.MaximumLoginLength
                ? null
                : normalized;
    }

    IReadOnlyCollection<string> NormalizeAutomaticLoginIdentifiers(
        string? value)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.Length
                > Authentication.IdentityLoginLimits.MaximumLoginLength)
        {
            return Array.Empty<string>();
        }

        var identifiers = new HashSet<string>(StringComparer.Ordinal);
        AddIfBounded(identifiers, NormalizeUserName(value));
        AddIfBounded(identifiers, NormalizeEmail(value));

        AddIfBounded(identifiers, NormalizePhoneLoginIdentifier(value));

        return identifiers
            .Take(
                Authentication.IdentityLoginLimits
                    .MaximumAutomaticLoginIdentifiers)
            .ToArray();
    }

    private static void AddIfBounded(
        HashSet<string> identifiers,
        string? identifier)
    {
        if (!string.IsNullOrEmpty(identifier)
            && identifier.Length
                <= Authentication.IdentityLoginLimits.MaximumLoginLength)
        {
            identifiers.Add(identifier);
        }
    }

    private static bool IsPhoneShaped(string value)
    {
        var candidate = value.AsSpan().Trim();
        var digitCount = 0;

        for (var index = 0; index < candidate.Length; index++)
        {
            var character = candidate[index];
            if (character is >= '0' and <= '9')
            {
                digitCount++;
                if (digitCount
                    > Authentication.IdentityLoginLimits.MaximumPhoneDigits)
                {
                    return false;
                }

                continue;
            }

            if (character == '+' && index == 0)
            {
                continue;
            }

            if (char.IsWhiteSpace(character)
                || character is '-' or '(' or ')' or '.')
            {
                continue;
            }

            return false;
        }

        return digitCount
            >= Authentication.IdentityLoginLimits.MinimumPhoneDigits;
    }
}
