using Skopka.Abstraction.OperationResult;
using Skopka.Identity.StepUp.Commands;
using Skopka.Identity.Verification;

namespace Skopka.Identity.StepUp;

public interface IIdentityStepUpService<TProfile>
{
    Task<OperationResult<IssuedVerificationChallenge>> BeginAsync(
        BeginStepUpCommand cmd,
        CancellationToken ct);

    Task<OperationResult<StepUpDecision>> AuthorizeAsync(
        AuthorizeStepUpCommand cmd,
        CancellationToken ct);
}
