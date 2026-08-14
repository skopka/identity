using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Verification;

namespace Skopka.Identity.Totp;

public sealed class TotpVerificationMethodProvider<TProfile>(
    ITotpFactorStore<TProfile> factorStore,
    ITotpCodeProvider codeProvider,
    ITotpSecretProtector secretProtector)
    : IVerificationMethodProvider
{
    public string Method => VerificationMethods.TimeBasedOneTimePassword;

    public async Task<OperationResult> CheckAvailabilityAsync(
        VerificationMethodContext context,
        CancellationToken ct)
    {
        var factor = await factorStore.FindByUserIdAsync(context.UserId, ct);
        return factor?.State == TotpFactorState.Enabled
            ? OperationResultFactory.Success()
            : OperationResultFactory.Fail(TotpErrors.NotEnabled());
    }

    public async Task<IssuedVerificationMethodChallenge> IssueAsync(
        VerificationMethodContext context,
        CancellationToken ct)
    {
        var factor = await factorStore.FindByUserIdAsync(context.UserId, ct);
        if (factor?.State != TotpFactorState.Enabled)
        {
            throw new InvalidOperationException(
                "The enabled TOTP factor disappeared while issuing a challenge.");
        }

        return new IssuedVerificationMethodChallenge(
            factor.EnrollmentId.ToString("N"),
            DeliveryCode: null);
    }

    public async Task<bool> VerifyAsync(
        VerificationMethodContext context,
        string verifier,
        string response,
        CancellationToken ct)
    {
        if (!Guid.TryParseExact(verifier, "N", out var enrollmentId))
        {
            return false;
        }

        var factor = await factorStore.FindByUserIdAsync(context.UserId, ct);
        if (!Matches(factor, enrollmentId))
        {
            return false;
        }

        if (!IsSixDigitCode(response))
        {
            var consumed = await factorStore.TryConsumeRecoveryCodeAsync(
                context.UserId,
                enrollmentId,
                TotpRecoveryCodes.Hash(response),
                DateTimeOffset.UtcNow,
                ct);
            return consumed.IsSuccess && consumed.Value;
        }

        if (!secretProtector.TryUnprotect(
                factor!.ProtectedSecret,
                out var secret))
        {
            return false;
        }

        var now = DateTimeOffset.UtcNow;
        if (!codeProvider.TryMatchCounter(
                secret,
                response,
                now,
                factor.LastAcceptedCounter,
                out var counter))
        {
            return false;
        }

        var accepted = await factorStore.TryAcceptCounterAsync(
            context.UserId,
            enrollmentId,
            factor.Version,
            counter,
            now,
            ct);
        if (accepted.IsSuccess && accepted.Value)
        {
            return true;
        }

        factor = await factorStore.FindByUserIdAsync(context.UserId, ct);
        if (!Matches(factor, enrollmentId)
            || !codeProvider.TryMatchCounter(
                secret,
                response,
                now,
                factor!.LastAcceptedCounter,
                out counter))
        {
            return false;
        }

        accepted = await factorStore.TryAcceptCounterAsync(
            context.UserId,
            enrollmentId,
            factor.Version,
            counter,
            now,
            ct);
        return accepted.IsSuccess && accepted.Value;
    }

    private static bool Matches(
        StoredTotpFactor? factor,
        Guid enrollmentId)
        => factor?.State == TotpFactorState.Enabled
            && factor.EnrollmentId == enrollmentId;

    private static bool IsSixDigitCode(string response)
        => response.Length == TotpOptions.StandardDigits
            && response.All(character => character is >= '0' and <= '9');
}
