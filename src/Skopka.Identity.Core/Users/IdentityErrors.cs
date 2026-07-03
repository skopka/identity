using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;

namespace Skopka.Identity.Users;

public static class IdentityErrors
{
    public static Error NotFound()
        => new(IdentityErrorCodes.UserNotFound, "User not found.", ErrorType.NotFound);

    public static Error Deleted()
        => new(IdentityErrorCodes.UserDeleted, "User is deleted.");

    public static Error Concurrency()
        => new(IdentityErrorCodes.ConcurrencyConflict, "Concurrency conflict.", ErrorType.Conflict);

    public static Error Forbidden(UserFlags flags)
        => new(IdentityErrorCodes.Forbidden, "User is protected and cannot be modified.", ErrorType.Forbidden, new { flags });

    public static Error Validation(string field, string message)
        => new(IdentityErrorCodes.Validation, "Validation failed.", ErrorType.Validation,
            new ValidationDetails(new Dictionary<string, string[]>
            {
                [field] = new[] { message }
            }));
}