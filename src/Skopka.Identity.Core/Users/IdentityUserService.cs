using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Metrics;
using Skopka.Identity.Users.Commands;
using Skopka.Identity.Users.Handles;

namespace Skopka.Identity.Users;

public sealed class IdentityUserService<TProfile>(
    IIdentityUserStore<TProfile> store,
    IIdentityNormalizer normalizer,
    IUserOperationPolicy policy,
    IIdentityMetrics metrics)
    : IIdentityUserService<TProfile>
{
    public async Task<OperationResult<IdentityUser<TProfile>>> CreateAsync(CreateUserCommand<TProfile> cmd, CancellationToken ct)
    {
        using var op = metrics.Begin("user.create");
        var now = DateTimeOffset.UtcNow;

        var handles = new NormalizedHandles(
            normalizer.NormalizeUserName(cmd.UserName),
            normalizer.NormalizeEmail(cmd.Email),
            normalizer.NormalizePhone(cmd.Phone));

        if (!policy.CanMutate(cmd.Flags))
            return Fail(op, IdentityErrors.Forbidden(cmd.Flags));

        var user = new NewIdentityUser<TProfile>(
            cmd.UserName,
            cmd.Email,
            cmd.Phone,
            cmd.Profile,
            cmd.Flags);

        var res = await store.CreateAsync(user, handles, now, ct);
        return Finish(op, res);
    }

    public async Task<OperationResult<IdentityUser<TProfile>>> ConfirmEmailAsync(ConfirmEmailCommand cmd, CancellationToken ct)
    {
        using var op = metrics.Begin("user.confirm_email");
        var now = DateTimeOffset.UtcNow;

        var normalized = normalizer.NormalizeEmail(cmd.Email);
        if (normalized is null)
            return Fail(op, IdentityErrors.Validation("email", "Email is required."));

        var user = await store.FindByIdAsync(cmd.UserId, ct);
        if (user is null)
            return Fail(op, IdentityErrors.NotFound());

        if (user.DeletedAt is not null)
            return Fail(op, IdentityErrors.Deleted());

        // Привязка к текущему значению (защита от "устаревшей ссылки")
        var currentNormalized = normalizer.NormalizeEmail(user.Email);
        if (!string.Equals(currentNormalized, normalized, StringComparison.Ordinal))
            return Fail(op, IdentityErrors.Validation("email", "Email has changed or does not match."));

        // CAS по текущей версии пользователя (версию из команды не требуем)
        var updated = new UpdatedHandles(
            user.UserName, normalizer.NormalizeUserName(user.UserName),
            user.Email, currentNormalized, true,
            user.Phone, normalizer.NormalizePhone(user.Phone), user.PhoneConfirmed);

        var res = await store.UpdateHandlesAsync(user.Id, user.Version, updated, now, ct);
        return Finish(op, res);
    }

    public async Task<OperationResult<IdentityUser<TProfile>>> ConfirmPhoneAsync(ConfirmPhoneCommand cmd, CancellationToken ct)
    {
        using var op = metrics.Begin("user.confirm_phone");
        var now = DateTimeOffset.UtcNow;

        var normalized = normalizer.NormalizePhone(cmd.Phone);
        if (normalized is null)
            return Fail(op, IdentityErrors.Validation("phone", "Phone is required."));

        var user = await store.FindByIdAsync(cmd.UserId, ct);
        if (user is null)
            return Fail(op, IdentityErrors.NotFound());

        if (user.DeletedAt is not null)
            return Fail(op, IdentityErrors.Deleted());

        var currentNormalized = normalizer.NormalizePhone(user.Phone);
        if (!string.Equals(currentNormalized, normalized, StringComparison.Ordinal))
            return Fail(op, IdentityErrors.Validation("phone", "Phone has changed or does not match."));

        var updated = new UpdatedHandles(
            user.UserName, normalizer.NormalizeUserName(user.UserName),
            user.Email, normalizer.NormalizeEmail(user.Email), user.EmailConfirmed,
            user.Phone, currentNormalized, true);

        var res = await store.UpdateHandlesAsync(user.Id, user.Version, updated, now, ct);
        return Finish(op, res);
    }

    public async Task<OperationResult<IdentityUser<TProfile>>> ChangeUserNameAsync(ChangeUserNameCommand cmd, CancellationToken ct)
        => await ChangeHandlesAsync("user.change_user_name", cmd.UserId, cmd.ExpectedVersion,
            mutate: user =>
            {
                var newUserName = normalizer.NormalizeUserName(cmd.NewUserName);

                return user with
                {
                    UserName = newUserName,
                    Version = cmd.ExpectedVersion, // store использует expectedVersion отдельно
                };
            },
            buildUpdated: user =>
            {
                var nUserName = normalizer.NormalizeUserName(cmd.NewUserName);
                return new UpdatedHandles(
                    cmd.NewUserName, nUserName,
                    user.Email, normalizer.NormalizeEmail(user.Email), user.EmailConfirmed,
                    user.Phone, normalizer.NormalizePhone(user.Phone), user.PhoneConfirmed);
            },
            ct);

    public async Task<OperationResult<IdentityUser<TProfile>>> ChangeEmailAsync(ChangeEmailCommand cmd, CancellationToken ct)
        => await ChangeHandlesAsync("user.change_email", cmd.UserId, cmd.ExpectedVersion,
            mutate: _ => null,
            buildUpdated: (user) =>
            {
                var nEmail = normalizer.NormalizeEmail(cmd.NewEmail);
                return new UpdatedHandles(
                    user.UserName, normalizer.NormalizeUserName(user.UserName),
                    cmd.NewEmail, nEmail, false, // сброс
                    user.Phone, normalizer.NormalizePhone(user.Phone), user.PhoneConfirmed);
            },
            ct);

    public async Task<OperationResult<IdentityUser<TProfile>>> ChangePhoneAsync(ChangePhoneCommand cmd, CancellationToken ct)
        => await ChangeHandlesAsync("user.change_phone", cmd.UserId, cmd.ExpectedVersion,
            mutate: _ => null,
            buildUpdated: (user) =>
            {
                var nPhone = normalizer.NormalizePhone(cmd.NewPhone);
                return new UpdatedHandles(
                    user.UserName, normalizer.NormalizeUserName(user.UserName),
                    user.Email, normalizer.NormalizeEmail(user.Email), user.EmailConfirmed,
                    cmd.NewPhone, nPhone, false);
            },
            ct);

    public async Task<OperationResult<IdentityUser<TProfile>>> PatchProfileAsync<TPatch>(PatchProfileCommand<TPatch> cmd, CancellationToken ct)
    {
        using var op = metrics.Begin("user.patch_profile");
        var now = DateTimeOffset.UtcNow;

        var user = await store.FindByIdAsync(cmd.UserId, ct);
        if (user is null) return Fail(op, IdentityErrors.NotFound());
        if (!policy.CanMutate(user.Flags)) return Fail(op, IdentityErrors.Forbidden(user.Flags));
        if (user.DeletedAt is not null) return Fail(op, IdentityErrors.Deleted());
        if (user.Version != cmd.ExpectedVersion) return Fail(op, IdentityErrors.Concurrency());

        var newProfile = user.Profile;

        if (cmd.Patch is IProfilePatch<TProfile> patcher)
        {
            patcher.ApplyTo(newProfile);
        }
        else if (cmd.Patch is TProfile replace)
        {
            newProfile = replace;
        }
        else
        {
            return Fail(op, IdentityErrors.Validation("profile", $"Unsupported patch type '{typeof(TPatch).Name}'."));
        }

        var res = await store.UpdateProfileAsync(user.Id, cmd.ExpectedVersion, newProfile, now, ct);
        return Finish(op, res);
    }

    public async Task<OperationResult<IdentityUser<TProfile>>> BlockAsync(BlockUserCommand cmd, CancellationToken ct)
    {
        using var op = metrics.Begin("user.block");
        var now = DateTimeOffset.UtcNow;

        var user = await store.FindByIdAsync(cmd.UserId, ct);
        if (user is null) return Fail(op, IdentityErrors.NotFound());
        if (!policy.CanMutate(user.Flags)) return Fail(op, IdentityErrors.Forbidden(user.Flags));
        if (user.DeletedAt is not null) return Fail(op, IdentityErrors.Deleted());
        if (user.Version != cmd.ExpectedVersion) return Fail(op, IdentityErrors.Concurrency());

        if (cmd.Until is not null && cmd.Until <= now)
            return Fail(op, IdentityErrors.Validation("until", "BlockedUntil must be in the future."));

        // blockedAt/blockedUntil: blockedAt у тебя в публичной модели есть, но в Store UpdateStateAsync принимает только deletedAt/blockedUntil
        var res = await store.UpdateStateAsync(user.Id, cmd.ExpectedVersion, user.DeletedAt, cmd.Until, now, ct);
        if (!res.IsSuccess) return Finish(op, OperationResultFactory.Fail<IdentityUser<TProfile>>(res.Errors));

        // Store UpdateStateAsync не возвращает пользователя -> перечитываем
        var refreshed = await store.FindByIdAsync(user.Id, ct);
        if (refreshed is null) return Fail(op, IdentityErrors.NotFound());

        op.Success();
        return OperationResultFactory.Success(refreshed);
    }

    public async Task<OperationResult<IdentityUser<TProfile>>> UnblockAsync(UnblockUserCommand cmd, CancellationToken ct)
    {
        using var op = metrics.Begin("user.unblock");
        var now = DateTimeOffset.UtcNow;

        var user = await store.FindByIdAsync(cmd.UserId, ct);
        if (user is null) return Fail(op, IdentityErrors.NotFound());
        if (!policy.CanMutate(user.Flags)) return Fail(op, IdentityErrors.Forbidden(user.Flags));
        if (user.DeletedAt is not null) return Fail(op, IdentityErrors.Deleted());
        if (user.Version != cmd.ExpectedVersion) return Fail(op, IdentityErrors.Concurrency());

        var res = await store.UpdateStateAsync(user.Id, cmd.ExpectedVersion, user.DeletedAt, blockedUntil: null, now, ct);
        if (!res.IsSuccess) return Finish(op, OperationResultFactory.Fail<IdentityUser<TProfile>>(res.Errors));

        var refreshed = await store.FindByIdAsync(user.Id, ct);
        if (refreshed is null) return Fail(op, IdentityErrors.NotFound());

        op.Success();
        return OperationResultFactory.Success(refreshed);
    }

    public async Task<OperationResult> DeleteAsync(DeleteUserCommand cmd, CancellationToken ct)
    {
        using var op = metrics.Begin("user.delete");
        var now = DateTimeOffset.UtcNow;

        var user = await store.FindByIdAsync(cmd.UserId, ct);
        if (user is null) return Finish(op, OperationResultFactory.Fail(IdentityErrors.NotFound()));
        if (!policy.CanMutate(user.Flags)) return Finish(op, OperationResultFactory.Fail(IdentityErrors.Forbidden(user.Flags)));
        if (user.Version != cmd.ExpectedVersion) return Finish(op, OperationResultFactory.Fail(IdentityErrors.Concurrency()));

        var deletedAt = user.DeletedAt ?? now; // идемпотентно
        var res = await store.UpdateStateAsync(user.Id, cmd.ExpectedVersion, deletedAt, user.BlockedUntil, now, ct);

        return Finish(op, res.IsSuccess ? OperationResultFactory.Success() : OperationResultFactory.Fail(res.Errors));
    }

    public async Task<OperationResult<IdentityUser<TProfile>>> RestoreAsync(RestoreUserCommand cmd, CancellationToken ct)
    {
        using var op = metrics.Begin("user.restore");
        var now = DateTimeOffset.UtcNow;

        var user = await store.FindByIdAsync(cmd.UserId, ct);
        if (user is null) return Fail(op, IdentityErrors.NotFound());
        if (!policy.CanMutate(user.Flags)) return Fail(op, IdentityErrors.Forbidden(user.Flags));
        if (user.Version != cmd.ExpectedVersion) return Fail(op, IdentityErrors.Concurrency());

        var res = await store.UpdateStateAsync(user.Id, cmd.ExpectedVersion, deletedAt: null, user.BlockedUntil, now, ct);
        if (!res.IsSuccess) return Finish(op, OperationResultFactory.Fail<IdentityUser<TProfile>>(res.Errors));

        var refreshed = await store.FindByIdAsync(user.Id, ct);
        if (refreshed is null) return Fail(op, IdentityErrors.NotFound());

        op.Success();
        return OperationResultFactory.Success(refreshed);
    }

    private async Task<OperationResult<IdentityUser<TProfile>>> ChangeHandlesAsync(
        string metricOp,
        Guid userId,
        long expectedVersion,
        Func<IdentityUser<TProfile>, IdentityUser<TProfile>?> mutate,
        Func<IdentityUser<TProfile>, UpdatedHandles> buildUpdated,
        CancellationToken ct)
    {
        using var op = metrics.Begin(metricOp);
        var now = DateTimeOffset.UtcNow;

        var user = await store.FindByIdAsync(userId, ct);
        if (user is null) return Fail(op, IdentityErrors.NotFound());
        if (!policy.CanMutate(user.Flags)) return Fail(op, IdentityErrors.Forbidden(user.Flags));
        if (user.DeletedAt is not null) return Fail(op, IdentityErrors.Deleted());
        if (user.Version != expectedVersion) return Fail(op, IdentityErrors.Concurrency());

        var updated = buildUpdated(user);

        var res = await store.UpdateHandlesAsync(userId, expectedVersion, updated, now, ct);
        return Finish(op, res);
    }

    private static OperationResult<IdentityUser<TProfile>> Fail(IIdentityOpScope op, Error err)
    {
        op.Failure(err.Code);
        return OperationResultFactory.Fail<IdentityUser<TProfile>>(err);
    }

    private static OperationResult<T> Finish<T>(IIdentityOpScope op, OperationResult<T> res)
    {
        if (res.IsSuccess) op.Success();
        else op.Failure(res.Errors.First().Code);
        return res;
    }

    private static OperationResult Finish(IIdentityOpScope op, OperationResult res)
    {
        if (res.IsSuccess) op.Success();
        else op.Failure(res.Errors.First().Code);
        return res;
    }
}
