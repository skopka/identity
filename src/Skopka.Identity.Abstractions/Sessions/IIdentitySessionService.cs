using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Users;

namespace Skopka.Identity.Sessions;

public interface IIdentitySessionService<TProfile>
{
    Task<OperationResult<IssuedIdentitySession>> CreateAsync(
        CreateIdentitySessionCommand command,
        CancellationToken ct);

    Task<OperationResult<IssuedIdentitySession>> RefreshAsync(
        RefreshIdentitySessionCommand command,
        CancellationToken ct);

    Task<OperationResult<IdentityUser<TProfile>>> ValidateAccessTokenAsync(
        string accessToken,
        CancellationToken ct);

    Task<OperationResult> RevokeAsync(
        RevokeIdentitySessionCommand command,
        CancellationToken ct);

    Task<OperationResult> RevokeAllAsync(
        RevokeAllIdentitySessionsCommand command,
        CancellationToken ct);

    Task<int> PruneAsync(CancellationToken ct);
}
