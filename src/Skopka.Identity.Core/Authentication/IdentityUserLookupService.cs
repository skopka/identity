using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Metrics;
using Skopka.Identity.Users;

using Skopka.Identity.Users.Handles;

namespace Skopka.Identity.Authentication;

public sealed class IdentityUserLookupService<TProfile>(
    IIdentityUserLookupStore<TProfile> store,
    IIdentityNormalizer normalizer,
    IIdentityMetrics metrics,
    IIdentityUserStore<TProfile>? userStore = null)
    : IIdentityUserLookupService<TProfile>
{
    public async Task<OperationResult<IdentityUser<TProfile>>> FindActiveByIdAsync(
        Guid userId, CancellationToken ct)
    {
        using var op = metrics.Begin("user.lookup.id");
        var user = userStore is null ? null : await userStore.FindByIdAsync(userId, ct);
        if (user is null || user.DeletedAt is not null) return Fail(op, IdentityErrors.NotFound());
        op.Success();
        return OperationResultFactory.Success(user);
    }

    public async Task<OperationResult<IdentityUser<TProfile>>>
        FindActiveByEmailAsync(
            string email,
            CancellationToken ct)
    {
        using var op = metrics.Begin("user.lookup.email");

        var normalizedEmail = normalizer.NormalizeEmail(email);
        if (string.IsNullOrWhiteSpace(normalizedEmail))
        {
            return Fail(
                op,
                IdentityErrors.Validation(
                    "email",
                    "Email is required."));
        }

        var user = await store.FindActiveByNormalizedEmailAsync(
            normalizedEmail,
            ct);
        if (user is null)
        {
            return Fail(op, IdentityErrors.NotFound());
        }

        op.Success();
        return OperationResultFactory.Success(user);
    }

    public Task<OperationResult<IdentityUser<TProfile>>>
        FindActiveByPhoneAsync(
            string phone,
            CancellationToken ct)
        => FindActiveByPhoneAsync(phone, null, ct);

    public async Task<OperationResult<IdentityUser<TProfile>>>
        FindActiveByPhoneAsync(
            string phone,
            string? phoneScope,
            CancellationToken ct)
    {
        using var op = metrics.Begin("user.lookup.phone");

        var scopeError = PhoneScopeValidator.Validate(phoneScope);
        if (scopeError is not null)
        {
            return Fail(op, scopeError);
        }

        var normalizedPhone = normalizer.NormalizePhoneLoginIdentifier(phone);
        if (string.IsNullOrWhiteSpace(normalizedPhone))
        {
            return Fail(
                op,
                IdentityErrors.Validation(
                    "phone",
                    "Phone is required."));
        }

        var user = await store.FindActiveByNormalizedPhoneAsync(
            normalizedPhone,
            phoneScope ?? IdentityPhoneScopes.Default,
            ct);
        if (user is null)
        {
            return Fail(op, IdentityErrors.NotFound());
        }

        op.Success();
        return OperationResultFactory.Success(user);
    }

    private static OperationResult<IdentityUser<TProfile>> Fail(
        IIdentityOpScope op,
        Error error)
    {
        op.Failure(error.Code);
        return OperationResultFactory.Fail<IdentityUser<TProfile>>(
            error);
    }
}
