using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Authentication;

namespace Skopka.Identity.Users.Handles;

internal static class LoginIdentifierKeyBuilder
{
    public static IReadOnlyCollection<string>? Create(
        IIdentityNormalizer normalizer,
        string? userName,
        string? email,
        string? phone,
        string? normalizedUserName,
        string? normalizedEmail,
        string? normalizedPhone,
        out Error? error)
    {
        var keys = new HashSet<string>(StringComparer.Ordinal);

        if (phone is not null && normalizedPhone is null)
        {
            error = IdentityErrors.Validation(
                "phone",
                "Phone is not a valid login identifier.");
            return null;
        }

        if (!TryAddAutomatic(keys, normalizer, "userName", userName, out error)
            || !TryAddAutomatic(keys, normalizer, "email", email, out error)
            || !TryAddAutomatic(keys, normalizer, "phone", phone, out error)
            || !TryAdd(keys, "userName", normalizedUserName, out error)
            || !TryAdd(keys, "email", normalizedEmail, out error)
            || !TryAdd(keys, "phone", normalizedPhone, out error))
        {
            return null;
        }

        error = null;
        return keys.ToArray();
    }

    private static bool TryAddAutomatic(
        HashSet<string> keys,
        IIdentityNormalizer normalizer,
        string field,
        string? value,
        out Error? error)
    {
        if (value is null)
        {
            error = null;
            return true;
        }

        if (value.Length > IdentityLoginLimits.MaximumLoginLength)
        {
            error = IdentityErrors.Validation(
                field,
                $"{field} cannot exceed "
                    + $"{IdentityLoginLimits.MaximumLoginLength} characters.");
            return false;
        }

        var normalizedKeys = normalizer
            .NormalizeAutomaticLoginIdentifiers(value)
            .Distinct(StringComparer.Ordinal)
            .Take(IdentityLoginLimits.MaximumAutomaticLoginIdentifiers);
        foreach (var normalizedKey in normalizedKeys)
        {
            if (!TryAdd(keys, field, normalizedKey, out error))
            {
                return false;
            }
        }

        error = null;
        return true;
    }

    private static bool TryAdd(
        HashSet<string> keys,
        string field,
        string? normalizedValue,
        out Error? error)
    {
        if (string.IsNullOrEmpty(normalizedValue))
        {
            error = null;
            return true;
        }

        if (normalizedValue.Length > IdentityLoginLimits.MaximumLoginLength)
        {
            error = IdentityErrors.Validation(
                field,
                $"The normalized {field} cannot exceed "
                    + $"{IdentityLoginLimits.MaximumLoginLength} characters.");
            return false;
        }

        keys.Add(normalizedValue);
        error = null;
        return true;
    }
}
