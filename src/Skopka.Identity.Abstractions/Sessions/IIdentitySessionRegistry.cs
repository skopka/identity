using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Users;

namespace Skopka.Identity.Sessions;

public interface IIdentitySessionRegistry<TProfile>
{
    Task<OperationResult<IdentitySessionInfo>> RegisterAsync(
        RegisterIdentitySessionCommand command,
        CancellationToken ct);

    Task<OperationResult<IdentityUser<TProfile>>> ValidateAsync(
        ValidateIdentitySessionCommand command,
        CancellationToken ct);

    Task<OperationResult> RevokeByIdAsync(
        RevokeIdentitySessionByIdCommand command,
        CancellationToken ct);

    Task<OperationResult> RevokeAllAsync(
        RevokeAllIdentitySessionsCommand command,
        CancellationToken ct);

    Task<OperationResult<IReadOnlyList<IdentitySessionInfo>>> ListAsync(
        ListIdentitySessionsCommand command,
        CancellationToken ct);

    Task<int> PruneAsync(CancellationToken ct);
}
