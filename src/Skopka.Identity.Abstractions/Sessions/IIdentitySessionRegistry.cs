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

    /// <summary>Validates a logical session and returns its trusted assurance. Legacy implementations report none.</summary>
    async Task<OperationResult<IdentityValidatedSession<TProfile>>> ValidateWithAssuranceAsync(
        ValidateIdentitySessionCommand command, CancellationToken ct)
    {
        var result = await ValidateAsync(command, ct);
        return result.IsSuccess
            ? OperationResultFactory.Success(new IdentityValidatedSession<TProfile>(result.Value, IdentitySessionAssurance.None))
            : OperationResultFactory.Fail<IdentityValidatedSession<TProfile>>(result.Errors);
    }

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
