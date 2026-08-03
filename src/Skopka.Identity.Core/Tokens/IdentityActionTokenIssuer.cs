using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Metrics;
using Skopka.Identity.Users;

namespace Skopka.Identity.Tokens;

public sealed class IdentityActionTokenIssuer<TProfile>(
    IIdentityUserStore<TProfile> userStore,
    IIdentityNormalizer normalizer,
    IUserOperationPolicy policy,
    IIdentityActionTokenProvider provider,
    IdentityActionTokenOptions options,
    IIdentityMetrics metrics)
    : IIdentityActionTokenIssuer<TProfile>
{
    public Task<OperationResult<IssuedIdentityActionToken>> IssueEmailConfirmationAsync(
        Guid userId,
        CancellationToken ct)
        => IssueAsync(
            "token.issue.email_confirmation",
            userId,
            IdentityActionTokenPurpose.EmailConfirmation,
            options.EmailConfirmationLifetime,
            user => normalizer.NormalizeEmail(user.Email),
            "email",
            ct);

    public Task<OperationResult<IssuedIdentityActionToken>> IssuePhoneConfirmationAsync(
        Guid userId,
        CancellationToken ct)
        => IssueAsync(
            "token.issue.phone_confirmation",
            userId,
            IdentityActionTokenPurpose.PhoneConfirmation,
            options.PhoneConfirmationLifetime,
            user => normalizer.NormalizePhoneLoginIdentifier(user.Phone),
            "phone",
            ct);

    public Task<OperationResult<IssuedIdentityActionToken>> IssuePasswordResetAsync(
        Guid userId,
        CancellationToken ct)
        => IssueAsync(
            "token.issue.password_reset",
            userId,
            IdentityActionTokenPurpose.PasswordReset,
            options.PasswordResetLifetime,
            _ => null,
            targetField: null,
            ct);

    private async Task<OperationResult<IssuedIdentityActionToken>> IssueAsync(
        string metricOperation,
        Guid userId,
        IdentityActionTokenPurpose purpose,
        TimeSpan lifetime,
        Func<IdentityUser<TProfile>, string?> getTarget,
        string? targetField,
        CancellationToken ct)
    {
        using var op = metrics.Begin(metricOperation);

        if (lifetime <= TimeSpan.Zero)
        {
            throw new InvalidOperationException(
                $"The configured lifetime for {purpose} must be positive.");
        }

        var user = await userStore.FindByIdAsync(userId, ct);
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

        var target = getTarget(user);
        if (targetField is not null && target is null)
        {
            return Fail(
                op,
                IdentityErrors.Validation(
                    targetField,
                    $"{char.ToUpperInvariant(targetField[0])}{targetField[1..]} is required."));
        }

        var issuedAt = DateTimeOffset.UtcNow;
        var expiresAt = issuedAt.Add(lifetime);
        var payload = new IdentityActionTokenPayload(
            IdentityActionTokenValidator.CurrentFormatVersion,
            purpose,
            user.Id,
            user.SecurityStamp,
            target,
            issuedAt,
            expiresAt);

        var token = provider.Generate(payload);

        op.Success();
        return OperationResultFactory.Success(
            new IssuedIdentityActionToken(token, expiresAt));
    }

    private static OperationResult<IssuedIdentityActionToken> Fail(
        IIdentityOpScope op,
        Error error)
    {
        op.Failure(error.Code);
        return OperationResultFactory.Fail<IssuedIdentityActionToken>(error);
    }
}
