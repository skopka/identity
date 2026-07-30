using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;

namespace Skopka.Identity.Registration;

internal static class IdentityRegistrationErrors
{
    public static Error PasswordHasherUnavailable()
        => new(
            IdentityErrorCodes.PasswordHasherUnavailable,
            "No password hasher is configured.");
}
