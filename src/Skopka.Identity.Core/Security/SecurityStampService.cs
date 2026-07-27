using System.Security.Cryptography;
using System.Text;
using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;
using Skopka.Identity.Metrics;
using Skopka.Identity.Users;

namespace Skopka.Identity.Security;

public sealed class SecurityStampService<TProfile>(
    IIdentityUserStore<TProfile> userStore,
    ISecurityStampGenerator securityStampGenerator,
    IUserOperationPolicy policy,
    IIdentityMetrics metrics)
    : ISecurityStampService<TProfile>
{
    public async Task<OperationResult<IdentityUser<TProfile>>> RotateAsync(
        RotateSecurityStampCommand cmd,
        CancellationToken ct)
    {
        using var op = metrics.Begin("security_stamp.rotate");
        var now = DateTimeOffset.UtcNow;

        var user = await userStore.FindByIdAsync(cmd.UserId, ct);
        if (user is null)
        {
            return Fail(op, IdentityErrors.NotFound());
        }

        if (!policy.CanMutate(user.Flags))
        {
            return Fail(op, IdentityErrors.Forbidden(user.Flags));
        }

        if (user.DeletedAt is not null)
        {
            return Fail(op, IdentityErrors.Deleted());
        }

        if (user.Version != cmd.ExpectedVersion)
        {
            return Fail(op, IdentityErrors.Concurrency());
        }

        var result = await userStore.UpdateSecurityStampAsync(
            user.Id,
            cmd.ExpectedVersion,
            securityStampGenerator.Generate(),
            now,
            ct);

        return Finish(op, result);
    }

    public async Task<bool> ValidateAsync(
        Guid userId,
        string securityStamp,
        CancellationToken ct)
    {
        using var op = metrics.Begin("security_stamp.validate");

        if (string.IsNullOrEmpty(securityStamp))
        {
            op.Failure(IdentityErrorCodes.InvalidCredentials);
            return false;
        }

        var user = await userStore.FindByIdAsync(userId, ct);
        var now = DateTimeOffset.UtcNow;
        var isValid = user is not null
            && user.DeletedAt is null
            && !IsBlocked(user, now)
            && FixedTimeEquals(user.SecurityStamp, securityStamp);

        if (isValid)
        {
            op.Success();
        }
        else
        {
            op.Failure(IdentityErrorCodes.InvalidCredentials);
        }

        return isValid;
    }

    private static bool IsBlocked(
        IdentityUser<TProfile> user,
        DateTimeOffset now)
        => user.BlockedAt is not null
            && (user.BlockedUntil is null || user.BlockedUntil > now);

    private static bool FixedTimeEquals(string expected, string provided)
    {
        var expectedBytes = Encoding.UTF8.GetBytes(expected);
        var providedBytes = Encoding.UTF8.GetBytes(provided);

        try
        {
            return CryptographicOperations.FixedTimeEquals(
                expectedBytes,
                providedBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedBytes);
            CryptographicOperations.ZeroMemory(providedBytes);
        }
    }

    private static OperationResult<IdentityUser<TProfile>> Fail(
        IIdentityOpScope op,
        Error error)
    {
        op.Failure(error.Code);
        return OperationResultFactory.Fail<IdentityUser<TProfile>>(error);
    }

    private static OperationResult<IdentityUser<TProfile>> Finish(
        IIdentityOpScope op,
        OperationResult<IdentityUser<TProfile>> result)
    {
        if (result.IsSuccess)
        {
            op.Success();
        }
        else
        {
            op.Failure(result.Errors.First().Code);
        }

        return result;
    }
}
