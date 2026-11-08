using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;
using Skopka.Identity.Users;

namespace Skopka.Identity.Authentication;

public interface IIdentityUserLookupService<TProfile>
{
    /// <summary>Finds a non-deleted user by id for trusted application workflows.</summary>
    Task<OperationResult<IdentityUser<TProfile>>> FindActiveByIdAsync(Guid userId, CancellationToken ct)
        => Task.FromResult(OperationResultFactory.Fail<IdentityUser<TProfile>>(
            new Error(IdentityErrorCodes.UserNotFound, "User not found.", ErrorType.NotFound)));

    Task<OperationResult<IdentityUser<TProfile>>> FindActiveByEmailAsync(
        string email,
        CancellationToken ct);

    Task<OperationResult<IdentityUser<TProfile>>> FindActiveByPhoneAsync(
        string phone,
        CancellationToken ct)
        => Task.FromResult(
            OperationResultFactory.Fail<IdentityUser<TProfile>>(
                new Error(
                    IdentityErrorCodes.UserNotFound,
                    "User not found.",
                    ErrorType.NotFound)));

    /// <summary>
    /// Finds the active user holding <paramref name="phone"/> in <paramref name="phoneScope"/>.
    /// The overload without a scope searches the default scope only.
    /// </summary>
    /// <remarks>
    /// Custom implementations without scope support resolve only the default scope and
    /// report every named scope as not found.
    /// </remarks>
    Task<OperationResult<IdentityUser<TProfile>>> FindActiveByPhoneAsync(
        string phone,
        string? phoneScope,
        CancellationToken ct)
        => string.IsNullOrEmpty(phoneScope)
            ? FindActiveByPhoneAsync(phone, ct)
            : Task.FromResult(
                OperationResultFactory.Fail<IdentityUser<TProfile>>(
                    new Error(
                        IdentityErrorCodes.UserNotFound,
                        "User not found.",
                        ErrorType.NotFound)));
}
