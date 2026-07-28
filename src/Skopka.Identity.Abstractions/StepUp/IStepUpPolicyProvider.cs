namespace Skopka.Identity.StepUp;

public interface IStepUpPolicyProvider<TProfile>
{
    Task<StepUpRequirement?> GetRequirementAsync(
        StepUpAuthorizationContext context,
        CancellationToken ct);
}
