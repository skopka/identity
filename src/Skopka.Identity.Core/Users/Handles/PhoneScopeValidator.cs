using Skopka.Abstraction.OperationResult;

namespace Skopka.Identity.Users.Handles;

internal static class PhoneScopeValidator
{
    /// <summary>
    /// Validates a trusted phone scope. <see langword="null"/> stays <see langword="null"/>
    /// so callers can decide whether it means "default" or "keep current".
    /// </summary>
    public static Error? Validate(string? scope)
    {
        if (scope is null || scope.Length == 0)
        {
            return null;
        }

        if (scope.Length > IdentityPhoneScopes.MaximumLength)
        {
            return IdentityErrors.Validation(
                "phoneScope",
                $"Phone scope cannot exceed {IdentityPhoneScopes.MaximumLength} characters.");
        }

        // Scopes are ordinal identifiers; whitespace or control characters would make two
        // visually equal scopes distinct.
        if (char.IsWhiteSpace(scope[0])
            || char.IsWhiteSpace(scope[^1])
            || scope.Any(char.IsControl))
        {
            return IdentityErrors.Validation(
                "phoneScope",
                "Phone scope cannot contain control characters or surrounding whitespace.");
        }

        return null;
    }

    /// <summary>Scope stored for a phone: no phone always lives in the default scope.</summary>
    public static string Effective(string? phone, string? scope)
        => phone is null ? IdentityPhoneScopes.Default : scope ?? IdentityPhoneScopes.Default;
}
