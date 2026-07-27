using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Credentials;
using Skopka.Identity.Errors;
using Skopka.Identity.Metrics;
using Skopka.Identity.Users;

namespace Skopka.Identity.Authentication;

public sealed class PasswordAuthenticationService<TProfile>(
    IIdentityUserLookupStore<TProfile> userLookupStore,
    IPasswordCredentialStore<TProfile> credentialStore,
    IIdentityNormalizer normalizer,
    IPasswordHasher passwordHasher,
    IPasswordVerificationTimingProtector timingProtector,
    IIdentityMetrics metrics)
    : IPasswordAuthenticationService<TProfile>
{
    public async Task<OperationResult<IdentityUser<TProfile>>> AuthenticateAsync(
        AuthenticatePasswordCommand cmd,
        CancellationToken ct)
    {
        using var op = metrics.Begin("authentication.password");
        var now = DateTimeOffset.UtcNow;

        if (string.IsNullOrWhiteSpace(cmd.Login))
        {
            return Fail(
                op,
                IdentityErrors.Validation("login", "Login is required."));
        }

        if (string.IsNullOrEmpty(cmd.Password))
        {
            return Fail(
                op,
                IdentityErrors.Validation("password", "Password is required."));
        }

        if (!Enum.IsDefined(cmd.Handle))
        {
            return Fail(
                op,
                IdentityErrors.Validation(
                    "handle",
                    "The password login handle is unsupported."));
        }

        var normalizedLogin = NormalizeLogin(cmd);
        if (normalizedLogin is null)
        {
            return Fail(
                op,
                IdentityErrors.Validation("login", "Login is invalid."));
        }

        var user = await FindUserAsync(cmd.Handle, normalizedLogin, ct);
        if (user is null)
        {
            _ = await credentialStore.FindPasswordVerifierAsync(Guid.Empty, ct);
            timingProtector.SimulateVerification(cmd.Password);
            return Fail(op, AuthenticationErrors.InvalidCredentials());
        }

        var passwordVerifier = await credentialStore.FindPasswordVerifierAsync(
            user.Id,
            ct);
        if (passwordVerifier is null)
        {
            timingProtector.SimulateVerification(cmd.Password);
            return Fail(op, AuthenticationErrors.InvalidCredentials());
        }

        var verification = passwordHasher.VerifyHashedPassword(
            passwordVerifier,
            cmd.Password);
        if (verification == PasswordVerificationResult.Failed)
        {
            return Fail(op, AuthenticationErrors.InvalidCredentials());
        }

        if (IsBlocked(user, now))
        {
            return Fail(op, AuthenticationErrors.Blocked());
        }

        if (verification == PasswordVerificationResult.SuccessRehashNeeded)
        {
            var updatedVerifier = passwordHasher.HashPassword(cmd.Password);
            var rehashResult = await credentialStore.ReplacePasswordVerifierAsync(
                user.Id,
                user.Version,
                passwordVerifier,
                updatedVerifier,
                now,
                ct);

            if (!rehashResult.IsSuccess
                && !rehashResult.Errors.Any(
                    error => error.Code == IdentityErrorCodes.ConcurrencyConflict))
            {
                return Finish(op, rehashResult);
            }

            if (rehashResult.IsSuccess)
            {
                var refreshedUser = await FindUserAsync(
                    cmd.Handle,
                    normalizedLogin,
                    ct);
                if (refreshedUser is null)
                {
                    return Fail(op, AuthenticationErrors.InvalidCredentials());
                }

                if (IsBlocked(refreshedUser, now))
                {
                    return Fail(op, AuthenticationErrors.Blocked());
                }

                user = refreshedUser;
            }
        }

        op.Success();
        return OperationResultFactory.Success(user);
    }

    private string? NormalizeLogin(AuthenticatePasswordCommand cmd)
        => cmd.Handle switch
        {
            PasswordLoginHandle.UserName => normalizer.NormalizeUserName(cmd.Login),
            PasswordLoginHandle.Email => normalizer.NormalizeEmail(cmd.Login),
            _ => null
        };

    private Task<IdentityUser<TProfile>?> FindUserAsync(
        PasswordLoginHandle handle,
        string normalizedLogin,
        CancellationToken ct)
        => handle switch
        {
            PasswordLoginHandle.UserName =>
                userLookupStore.FindActiveByNormalizedUserNameAsync(
                    normalizedLogin,
                    ct),
            PasswordLoginHandle.Email =>
                userLookupStore.FindActiveByNormalizedEmailAsync(
                    normalizedLogin,
                    ct),
            _ => Task.FromResult<IdentityUser<TProfile>?>(null)
        };

    private static bool IsBlocked(
        IdentityUser<TProfile> user,
        DateTimeOffset now)
        => user.BlockedAt is not null
            && (user.BlockedUntil is null || user.BlockedUntil > now);

    private static OperationResult<IdentityUser<TProfile>> Fail(
        IIdentityOpScope op,
        Error error)
    {
        op.Failure(error.Code);
        return OperationResultFactory.Fail<IdentityUser<TProfile>>(error);
    }

    private static OperationResult<IdentityUser<TProfile>> Finish(
        IIdentityOpScope op,
        OperationResult result)
    {
        op.Failure(result.Errors.First().Code);
        return OperationResultFactory.Fail<IdentityUser<TProfile>>(result.Errors);
    }
}
