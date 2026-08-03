using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Metrics;
using Skopka.Identity.Users;

namespace Skopka.Identity.Authentication;

public sealed class IdentityUserLookupService<TProfile>(
    IIdentityUserLookupStore<TProfile> store,
    IIdentityNormalizer normalizer,
    IIdentityMetrics metrics)
    : IIdentityUserLookupService<TProfile>
{
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

    public async Task<OperationResult<IdentityUser<TProfile>>>
        FindActiveByPhoneAsync(
            string phone,
            CancellationToken ct)
    {
        using var op = metrics.Begin("user.lookup.phone");

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
