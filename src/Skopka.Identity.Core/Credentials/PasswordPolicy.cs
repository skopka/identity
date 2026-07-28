using System.Text;
using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Users;

namespace Skopka.Identity.Credentials;

internal static class PasswordPolicy
{
    public static PasswordPolicyOptions ValidateOptions(
        PasswordPolicyOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (options.MinimumLength < PasswordPolicyOptions.MinimumAllowedLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options),
                $"MinimumLength must be at least {PasswordPolicyOptions.MinimumAllowedLength}.");
        }

        if (options.MaximumLength
            < PasswordPolicyOptions.MinimumSupportedMaximumLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options),
                $"MaximumLength must be at least {PasswordPolicyOptions.MinimumSupportedMaximumLength}.");
        }

        if (options.MaximumLength > PasswordPolicyOptions.MaximumAllowedLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options),
                $"MaximumLength must not exceed {PasswordPolicyOptions.MaximumAllowedLength}.");
        }

        if (options.MinimumLength > options.MaximumLength)
        {
            throw new ArgumentException(
                "MinimumLength must not exceed MaximumLength.",
                nameof(options));
        }

        return options;
    }

    public static Error? ValidateInput(
        string? password,
        string field,
        PasswordPolicyOptions options)
    {
        if (string.IsNullOrEmpty(password))
        {
            return IdentityErrors.Validation(field, "Password is required.");
        }

        return ExceedsMaximumLength(password, options.MaximumLength)
            ? IdentityErrors.Validation(
                field,
                $"Password must not exceed {options.MaximumLength} characters.")
            : null;
    }

    public static Error? ValidateNewPassword(
        string? password,
        PasswordPolicyOptions options)
    {
        if (string.IsNullOrEmpty(password))
        {
            return IdentityErrors.Validation(
                "newPassword",
                "Password is required.");
        }

        if (ExceedsMaximumLength(password, options.MaximumLength))
        {
            return PasswordCredentialErrors.Rejected(
                $"Password must not exceed {options.MaximumLength} characters.");
        }

        return CountRunes(password, options.MinimumLength) < options.MinimumLength
            ? PasswordCredentialErrors.Rejected(
                $"Password must contain at least {options.MinimumLength} characters.")
            : null;
    }

    private static bool ExceedsMaximumLength(
        string password,
        int maximumLength)
    {
        if (password.Length > maximumLength * 2)
        {
            return true;
        }

        return CountRunes(password, maximumLength + 1) > maximumLength;
    }

    private static int CountRunes(string value, int stopAfter)
    {
        var count = 0;
        foreach (Rune _ in value.EnumerateRunes())
        {
            count++;
            if (count >= stopAfter)
            {
                break;
            }
        }

        return count;
    }
}
