using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Users;

namespace Skopka.Identity.ExternalLogins;

internal static class ExternalLoginPolicy
{
    public static ExternalLoginKey? Normalize(
        ExternalLoginKey? login,
        out Error? error)
    {
        if (login is null)
        {
            error = IdentityErrors.Validation(
                "login",
                "External login is required.");
            return null;
        }

        var provider = login.Provider?.Trim();
        if (string.IsNullOrWhiteSpace(provider))
        {
            error = IdentityErrors.Validation(
                "provider",
                "External login provider is required.");
            return null;
        }

        if (provider.Length > ExternalLoginLimits.MaximumProviderLength)
        {
            error = IdentityErrors.Validation(
                "provider",
                $"External login provider must not exceed {ExternalLoginLimits.MaximumProviderLength} characters.");
            return null;
        }

        if (string.IsNullOrWhiteSpace(login.Subject))
        {
            error = IdentityErrors.Validation(
                "subject",
                "External login subject is required.");
            return null;
        }

        if (login.Subject.Length > ExternalLoginLimits.MaximumSubjectLength)
        {
            error = IdentityErrors.Validation(
                "subject",
                $"External login subject must not exceed {ExternalLoginLimits.MaximumSubjectLength} characters.");
            return null;
        }

        error = null;
        return new ExternalLoginKey(
            provider.ToUpperInvariant(),
            login.Subject);
    }
}
