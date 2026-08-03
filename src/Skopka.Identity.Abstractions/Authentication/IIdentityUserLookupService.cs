using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;
using Skopka.Identity.Users;

namespace Skopka.Identity.Authentication;

public interface IIdentityUserLookupService<TProfile>
{
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
}
