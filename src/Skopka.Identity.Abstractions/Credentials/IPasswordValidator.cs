using Skopka.Abstraction.OperationResult;

namespace Skopka.Identity.Credentials;

public interface IPasswordValidator<TProfile>
{
    Task<OperationResult> ValidateAsync(
        PasswordValidationContext<TProfile> context,
        CancellationToken ct);
}
