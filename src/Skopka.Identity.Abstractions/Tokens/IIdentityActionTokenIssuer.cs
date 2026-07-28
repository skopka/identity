using Skopka.Abstraction.OperationResult;

namespace Skopka.Identity.Tokens;

public interface IIdentityActionTokenIssuer<TProfile>
{
    Task<OperationResult<IssuedIdentityActionToken>> IssueEmailConfirmationAsync(
        Guid userId,
        CancellationToken ct);

    Task<OperationResult<IssuedIdentityActionToken>> IssuePhoneConfirmationAsync(
        Guid userId,
        CancellationToken ct);

    Task<OperationResult<IssuedIdentityActionToken>> IssuePasswordResetAsync(
        Guid userId,
        CancellationToken ct);
}
