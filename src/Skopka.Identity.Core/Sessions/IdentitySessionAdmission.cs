using Skopka.Abstraction.OperationResult;

namespace Skopka.Identity.Sessions;

internal static class IdentitySessionAdmission
{
    public static async Task<OperationResult> CheckAsync<TProfile>(
        IEnumerable<IIdentitySessionAdmissionPolicy<TProfile>>? policies,
        IdentitySessionAdmissionContext<TProfile> context, CancellationToken ct)
    {
        if (policies is not null)
            foreach (var policy in policies)
            {
                var result = await policy.CheckAsync(context, ct);
                if (!result.IsSuccess) return result;
            }
        return OperationResultFactory.Success();
    }

    public static bool IsValid(IdentitySessionContext? context)
        => context is null || (ValidValue(context.Scope) && ValidValue(context.AuthenticationMethod));

    private static bool ValidValue(string? value)
        => !string.IsNullOrWhiteSpace(value) && value.Length <= IdentitySessionContext.MaximumValueLength
            && !value.Any(char.IsControl);

    public static IdentitySessionAssurance Known(IdentitySessionAssurance assurance)
        => Enum.IsDefined(assurance) ? assurance : IdentitySessionAssurance.None;
}
