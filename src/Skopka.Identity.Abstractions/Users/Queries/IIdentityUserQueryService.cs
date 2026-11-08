using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;

namespace Skopka.Identity.Users.Queries;

public interface IIdentityUserQueryService<TProfile>
{
    Task<OperationResult<IdentityUserPage<TProfile>>> QueryAsync(
        IdentityUserQuery query,
        CancellationToken ct);

    /// <summary>
    /// Counts users matching the same search, status, flags and role filter as
    /// <see cref="QueryAsync"/>, in one store query. Cursor and page size are ignored
    /// apart from validation.
    /// </summary>
    /// <remarks>Custom implementations fail closed by default.</remarks>
    Task<OperationResult<long>> CountAsync(
        IdentityUserQuery query,
        CancellationToken ct)
        => Task.FromResult(OperationResultFactory.Fail<long>(new Error(
            IdentityErrorCodes.UserQueryUnsupported,
            "This user query is not supported.",
            ErrorType.Forbidden)));
}
