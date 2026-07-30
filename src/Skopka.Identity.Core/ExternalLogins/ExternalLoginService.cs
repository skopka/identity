using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Metrics;
using Skopka.Identity.Security;
using Skopka.Identity.SecurityEvents;
using Skopka.Identity.Users;

namespace Skopka.Identity.ExternalLogins;

public sealed class ExternalLoginService<TProfile>(
    IIdentityUserStore<TProfile> userStore,
    IExternalLoginStore<TProfile> loginStore,
    IUserOperationPolicy policy,
    ISecurityStampGenerator securityStampGenerator,
    IIdentityMetrics metrics,
    IIdentitySecurityEventObserver? securityEvents = null)
    : IExternalLoginService<TProfile>
{
    public async Task<OperationResult<IdentityUser<TProfile>>> ResolveAsync(
        ExternalLoginKey login,
        CancellationToken ct)
    {
        using var op = metrics.Begin("external_login.resolve");

        var normalized = ExternalLoginPolicy.Normalize(login, out var error);
        if (error is not null)
        {
            return Fail<IdentityUser<TProfile>>(op, error);
        }

        var user = await loginStore.FindActiveUserAsync(normalized!, ct);
        if (user is null)
        {
            return Fail<IdentityUser<TProfile>>(
                op,
                ExternalLoginErrors.NotFound());
        }

        op.Success();
        return OperationResultFactory.Success(user);
    }

    public async Task<OperationResult<IReadOnlyList<ExternalLoginInfo>>> ListAsync(
        Guid userId,
        CancellationToken ct)
    {
        using var op = metrics.Begin("external_login.list");

        var user = await userStore.FindByIdAsync(userId, ct);
        if (user is null)
        {
            return Fail<IReadOnlyList<ExternalLoginInfo>>(
                op,
                IdentityErrors.NotFound());
        }

        if (user.DeletedAt is not null)
        {
            return Fail<IReadOnlyList<ExternalLoginInfo>>(
                op,
                IdentityErrors.Deleted());
        }

        var logins = await loginStore.ListAsync(userId, ct);
        op.Success();
        return OperationResultFactory.Success(logins);
    }

    public Task<OperationResult<IdentityUser<TProfile>>> LinkAsync(
        LinkExternalLoginCommand command,
        CancellationToken ct)
        => MutateAsync(
            "external_login.link",
            command.UserId,
            command.ExpectedVersion,
            command.Login,
            link: true,
            ct);

    public Task<OperationResult<IdentityUser<TProfile>>> UnlinkAsync(
        UnlinkExternalLoginCommand command,
        CancellationToken ct)
        => MutateAsync(
            "external_login.unlink",
            command.UserId,
            command.ExpectedVersion,
            command.Login,
            link: false,
            ct);

    private async Task<OperationResult<IdentityUser<TProfile>>> MutateAsync(
        string operation,
        Guid userId,
        long expectedVersion,
        ExternalLoginKey login,
        bool link,
        CancellationToken ct)
    {
        using var op = metrics.Begin(operation);

        var normalized = ExternalLoginPolicy.Normalize(login, out var error);
        if (error is not null)
        {
            return Fail<IdentityUser<TProfile>>(op, error);
        }

        var user = await userStore.FindByIdAsync(userId, ct);
        if (user is null)
        {
            return Fail<IdentityUser<TProfile>>(
                op,
                IdentityErrors.NotFound());
        }

        if (!policy.CanMutate(user.Flags))
        {
            return Fail<IdentityUser<TProfile>>(
                op,
                IdentityErrors.Forbidden(user.Flags));
        }

        if (user.DeletedAt is not null)
        {
            return Fail<IdentityUser<TProfile>>(
                op,
                IdentityErrors.Deleted());
        }

        if (user.Version != expectedVersion)
        {
            return Fail<IdentityUser<TProfile>>(
                op,
                IdentityErrors.Concurrency());
        }

        var now = DateTimeOffset.UtcNow;
        var newSecurityStamp = securityStampGenerator.Generate();
        var result = link
            ? await loginStore.LinkAsync(
                userId,
                expectedVersion,
                normalized!,
                newSecurityStamp,
                now,
                ct)
            : await loginStore.UnlinkAsync(
                userId,
                expectedVersion,
                normalized!,
                newSecurityStamp,
                now,
                ct);

        if (result.IsSuccess
            && (!link || result.Value.Version != expectedVersion))
        {
            securityEvents.Observe(
                link
                    ? IdentitySecurityEventTypes.ExternalLoginLinked
                    : IdentitySecurityEventTypes.ExternalLoginUnlinked,
                now,
                userId);
        }

        return Finish(op, result);
    }

    private static OperationResult<T> Fail<T>(
        IIdentityOpScope op,
        Error error)
    {
        op.Failure(error.Code);
        return OperationResultFactory.Fail<T>(error);
    }

    private static OperationResult<T> Finish<T>(
        IIdentityOpScope op,
        OperationResult<T> result)
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
