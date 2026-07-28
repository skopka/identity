using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;

namespace Skopka.Identity.Roles;

internal static class IdentityRoleErrors
{
    public static Error NotFound()
        => new(
            IdentityErrorCodes.RoleNotFound,
            "Role not found.",
            ErrorType.NotFound);

    public static Error DuplicateName()
        => new(
            IdentityErrorCodes.DuplicateRoleName,
            "Role name is already in use.",
            ErrorType.Conflict);

    public static Error Validation(string field, string message)
        => new(
            IdentityErrorCodes.Validation,
            "Validation failed.",
            ErrorType.Validation,
            new ValidationDetails(new Dictionary<string, string[]>
            {
                [field] = [message]
            }));
}
