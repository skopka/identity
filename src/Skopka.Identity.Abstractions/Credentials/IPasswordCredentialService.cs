using Skopka.Abstraction.OperationResult;

namespace Skopka.Identity.Credentials;

public interface IPasswordCredentialService<TProfile>
{
    Task<OperationResult> SetPasswordAsync(
        SetPasswordCommand cmd,
        CancellationToken ct);

    Task<OperationResult> ChangePasswordAsync(
        ChangePasswordCommand cmd,
        CancellationToken ct);

    Task<OperationResult> RemovePasswordAsync(
        RemovePasswordCommand cmd,
        CancellationToken ct);

    Task<OperationResult> VerifyPasswordAsync(
        VerifyPasswordCommand cmd,
        CancellationToken ct);
}
