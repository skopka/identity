using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Credentials;
using Skopka.Identity.ExternalLogins;
using Skopka.Identity.Metrics;
using Skopka.Identity.Users;

namespace Skopka.Identity.SignInMethods;

public sealed class IdentitySignInMethodQueryService<TProfile>(
    IIdentityUserStore<TProfile> userStore,
    IPasswordCredentialStore<TProfile> credentialStore,
    IExternalLoginStore<TProfile> externalLoginStore,
    IIdentityMetrics metrics)
    : IIdentitySignInMethodQueryService<TProfile>
{
    public async Task<OperationResult<SignInMethodSnapshot>> GetAsync(
        Guid userId,
        CancellationToken ct)
    {
        using var op = metrics.Begin("sign_in_method.get");

        if (userId == Guid.Empty)
        {
            return Fail(
                op,
                IdentityErrors.Validation("userId", "UserId is required."));
        }

        var user = await userStore.FindByIdAsync(userId, ct);
        if (user is null)
        {
            return Fail(op, IdentityErrors.NotFound());
        }

        if (user.DeletedAt is not null)
        {
            return Fail(op, IdentityErrors.Deleted());
        }

        var hasPassword = await credentialStore.FindPasswordVerifierAsync(userId, ct)
            is not null;
        var externalLogins = await externalLoginStore.ListAsync(userId, ct);

        op.Success();
        return OperationResultFactory.Success(
            new SignInMethodSnapshot(
                user.Id,
                user.Version,
                hasPassword,
                externalLogins.ToArray()));
    }

    private static OperationResult<SignInMethodSnapshot> Fail(
        IIdentityOpScope op,
        Error error)
    {
        op.Failure(error.Code);
        return OperationResultFactory.Fail<SignInMethodSnapshot>(error);
    }
}
