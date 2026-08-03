using System.Security.Cryptography;
using System.Text;
using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Credentials;
using Skopka.Identity.Errors;
using Skopka.Identity.Metrics;
using Skopka.Identity.RateLimiting;
using Skopka.Identity.Users;

namespace Skopka.Identity.Authentication;

public sealed class PasswordAuthenticationService<TProfile>(
    IIdentityUserLookupStore<TProfile> userLookupStore,
    IPasswordCredentialStore<TProfile> credentialStore,
    IIdentityNormalizer normalizer,
    IPasswordHasher passwordHasher,
    IPasswordVerificationTimingProtector timingProtector,
    IIdentityMetrics metrics,
    PasswordPolicyOptions passwordPolicyOptions,
    IdentityRateLimitOptions rateLimitOptions,
    IEnumerable<IIdentityRateLimiter<TProfile>> rateLimiters)
    : IPasswordAuthenticationService<TProfile>
{
    private readonly PasswordPolicyOptions passwordPolicy =
        PasswordPolicy.ValidateOptions(passwordPolicyOptions);
    private readonly IIdentityRateLimiter<TProfile>? rateLimiter =
        rateLimiters.FirstOrDefault();

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

        if (cmd.Login.Length > IdentityLoginLimits.MaximumLoginLength)
        {
            return Fail(
                op,
                IdentityErrors.Validation(
                    "login",
                    $"Login cannot exceed "
                        + $"{IdentityLoginLimits.MaximumLoginLength} characters."));
        }

        var passwordError = PasswordPolicy.ValidateInput(
            cmd.Password,
            "password",
            passwordPolicy);
        if (passwordError is not null)
        {
            return Fail(op, passwordError);
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

        if (cmd.ClientKey is { Length: > RateLimitLimits.MaximumClientKeyLength })
        {
            return Fail(
                op,
                IdentityErrors.Validation(
                    "clientKey",
                    "ClientKey exceeds the supported length."));
        }

        if (rateLimiter is not null)
        {
            var clientKey = NormalizeClientKey(cmd.ClientKey);
            if (clientKey is not null)
            {
                var clientDecision = await rateLimiter.HitAsync(
                    new RateLimitRequest(
                        IdentityRateLimitScopes.PasswordClient,
                        clientKey,
                        rateLimitOptions.PasswordClientPermitLimit,
                        rateLimitOptions.PasswordClientWindow),
                    ct);
                if (!clientDecision.IsAllowed)
                {
                    return Fail(
                        op,
                        IdentityRateLimitErrors.Exceeded(
                            clientDecision.RetryAfter));
                }
            }
        }

        var user = await FindUserAsync(cmd.Handle, normalizedLogin, ct);
        var accountRequest = new RateLimitRequest(
            IdentityRateLimitScopes.PasswordAccount,
            CreateAccountKey(cmd.Handle, normalizedLogin, user?.Id),
            rateLimitOptions.PasswordAccountPermitLimit,
            rateLimitOptions.PasswordAccountWindow);

        if (rateLimiter is not null)
        {
            var accountDecision = await rateLimiter.CheckAsync(
                accountRequest,
                ct);
            if (!accountDecision.IsAllowed)
            {
                timingProtector.SimulateVerification(cmd.Password);
                return Fail(
                    op,
                    IdentityRateLimitErrors.Exceeded(
                        accountDecision.RetryAfter));
            }
        }

        if (user is null)
        {
            _ = await credentialStore.FindPasswordVerifierAsync(Guid.Empty, ct);
            timingProtector.SimulateVerification(cmd.Password);
            return await InvalidCredentialsAsync(op, accountRequest, ct);
        }

        var passwordVerifier = await credentialStore.FindPasswordVerifierAsync(
            user.Id,
            ct);
        if (passwordVerifier is null)
        {
            timingProtector.SimulateVerification(cmd.Password);
            return await InvalidCredentialsAsync(op, accountRequest, ct);
        }

        var verification = passwordHasher.VerifyHashedPassword(
            passwordVerifier,
            cmd.Password);
        if (verification == PasswordVerificationResult.Failed)
        {
            return await InvalidCredentialsAsync(op, accountRequest, ct);
        }

        if (rateLimiter is not null)
        {
            await rateLimiter.ResetAsync(
                accountRequest.Scope,
                accountRequest.Key,
                ct);
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
                newSecurityStamp: null,
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
                var refreshedUser = await FindUserAfterRehashAsync(
                    cmd.Handle,
                    normalizedLogin,
                    ct);
                if (refreshedUser is null || refreshedUser.Id != user.Id)
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

    private NormalizedLogin? NormalizeLogin(AuthenticatePasswordCommand cmd)
    {
        if (cmd.Handle == PasswordLoginHandle.Automatic)
        {
            var normalizedKeys = normalizer
                .NormalizeAutomaticLoginIdentifiers(cmd.Login)
                .Where(key => !string.IsNullOrEmpty(key))
                .Where(
                    key => key.Length
                        <= IdentityLoginLimits.MaximumLoginLength)
                .Distinct(StringComparer.Ordinal)
                .Take(IdentityLoginLimits.MaximumAutomaticLoginIdentifiers)
                .ToArray();

            return normalizedKeys.Length == 0
                ? null
                : new NormalizedLogin(
                    null,
                    normalizedKeys,
                    normalizer.NormalizePhoneLoginIdentifier(cmd.Login));
        }

        var normalizedValue = cmd.Handle switch
        {
            PasswordLoginHandle.UserName =>
                normalizer.NormalizeUserName(cmd.Login),
            PasswordLoginHandle.Email => normalizer.NormalizeEmail(cmd.Login),
            PasswordLoginHandle.Phone =>
                normalizer.NormalizePhoneLoginIdentifier(cmd.Login),
            _ => null
        };

        return string.IsNullOrEmpty(normalizedValue)
            || normalizedValue.Length > IdentityLoginLimits.MaximumLoginLength
                ? null
                : new NormalizedLogin(
                    normalizedValue,
                    null,
                    cmd.Handle == PasswordLoginHandle.Phone
                        ? normalizedValue
                        : null);
    }

    private static string CreateAccountKey(
        PasswordLoginHandle handle,
        NormalizedLogin login,
        Guid? userId)
    {
        if (userId is not null)
        {
            return $"user:{userId.Value:N}";
        }

        if (login.NormalizedValue is not null)
        {
            return $"{(int)handle}:{login.NormalizedValue}";
        }

        var canonicalKeys = login.NormalizedPhoneIdentifier is not null
            ? $"phone:{login.NormalizedPhoneIdentifier.Length}:"
                + login.NormalizedPhoneIdentifier
            : string.Concat(
                login.NormalizedKeys!
                    .Order(StringComparer.Ordinal)
                    .Select(key => $"{key.Length}:{key}"));
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(canonicalKeys));
        return $"{(int)handle}:{Convert.ToHexString(digest)}";
    }

    private async Task<IdentityUser<TProfile>?> FindUserAsync(
        PasswordLoginHandle handle,
        NormalizedLogin login,
        CancellationToken ct)
    {
        if (handle == PasswordLoginHandle.Automatic)
        {
            var users = await userLookupStore
                .FindActiveByNormalizedLoginIdentifiersAsync(
                    login.NormalizedKeys!,
                    ct);
            var distinctUsers = users
                .DistinctBy(user => user.Id)
                .Take(IdentityLoginLimits.MaximumResolvedUsers)
                .ToArray();
            return distinctUsers.Length == 1 ? distinctUsers[0] : null;
        }

        return handle switch
        {
            PasswordLoginHandle.UserName =>
                await userLookupStore.FindActiveByNormalizedUserNameAsync(
                    login.NormalizedValue!,
                    ct),
            PasswordLoginHandle.Email =>
                await userLookupStore.FindActiveByNormalizedEmailAsync(
                    login.NormalizedValue!,
                    ct),
            PasswordLoginHandle.Phone =>
                await userLookupStore.FindActiveByNormalizedPhoneAsync(
                    login.NormalizedValue!,
                    ct),
            _ => null
        };
    }

    private Task<IdentityUser<TProfile>?> FindUserAfterRehashAsync(
        PasswordLoginHandle handle,
        NormalizedLogin login,
        CancellationToken ct)
        => FindUserAsync(handle, login, ct);

    private async Task<OperationResult<IdentityUser<TProfile>>>
        InvalidCredentialsAsync(
            IIdentityOpScope op,
            RateLimitRequest accountRequest,
            CancellationToken ct)
    {
        if (rateLimiter is not null)
        {
            await rateLimiter.HitAsync(accountRequest, ct);
        }

        return Fail(op, AuthenticationErrors.InvalidCredentials());
    }

    private static string? NormalizeClientKey(string? clientKey)
        => string.IsNullOrWhiteSpace(clientKey)
            ? null
            : clientKey.Trim();

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

    private sealed record NormalizedLogin(
        string? NormalizedValue,
        IReadOnlyCollection<string>? NormalizedKeys,
        string? NormalizedPhoneIdentifier);
}
