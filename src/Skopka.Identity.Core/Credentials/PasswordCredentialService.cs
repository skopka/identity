using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;
using Skopka.Identity.Metrics;
using Skopka.Identity.Security;
using Skopka.Identity.Users;

namespace Skopka.Identity.Credentials;

public sealed class PasswordCredentialService<TProfile>(
    IIdentityUserStore<TProfile> userStore,
    IPasswordCredentialStore<TProfile> credentialStore,
    IPasswordHasher passwordHasher,
    ISecurityStampGenerator securityStampGenerator,
    IUserOperationPolicy policy,
    IIdentityMetrics metrics)
    : IPasswordCredentialService<TProfile>
{
    public async Task<OperationResult> SetPasswordAsync(
        SetPasswordCommand cmd,
        CancellationToken ct)
    {
        using var op = metrics.Begin("credential.password.set");
        var now = DateTimeOffset.UtcNow;

        var validationError = ValidatePassword(cmd.NewPassword, "newPassword");
        if (validationError is not null)
        {
            return Fail(op, validationError);
        }

        var user = await userStore.FindByIdAsync(cmd.UserId, ct);
        var userError = ValidateMutableUser(user, cmd.ExpectedVersion);
        if (userError is not null)
        {
            return Fail(op, userError);
        }

        var currentVerifier = await credentialStore.FindPasswordVerifierAsync(cmd.UserId, ct);
        if (currentVerifier is not null)
        {
            return Fail(op, PasswordCredentialErrors.AlreadySet());
        }

        var passwordVerifier = passwordHasher.HashPassword(cmd.NewPassword);
        var result = await credentialStore.ReplacePasswordVerifierAsync(
            cmd.UserId,
            cmd.ExpectedVersion,
            expectedPasswordVerifier: null,
            passwordVerifier,
            securityStampGenerator.Generate(),
            now,
            ct);

        return Finish(op, result);
    }

    public async Task<OperationResult> ChangePasswordAsync(
        ChangePasswordCommand cmd,
        CancellationToken ct)
    {
        using var op = metrics.Begin("credential.password.change");
        var now = DateTimeOffset.UtcNow;

        var validationError = ValidatePassword(cmd.CurrentPassword, "currentPassword")
            ?? ValidatePassword(cmd.NewPassword, "newPassword");
        if (validationError is not null)
        {
            return Fail(op, validationError);
        }

        var user = await userStore.FindByIdAsync(cmd.UserId, ct);
        var userError = ValidateMutableUser(user, cmd.ExpectedVersion);
        if (userError is not null)
        {
            return Fail(op, userError);
        }

        var currentVerifier = await credentialStore.FindPasswordVerifierAsync(cmd.UserId, ct);
        if (currentVerifier is null)
        {
            return Fail(op, PasswordCredentialErrors.NotSet());
        }

        var verification = passwordHasher.VerifyHashedPassword(
            currentVerifier,
            cmd.CurrentPassword);
        if (verification == PasswordVerificationResult.Failed)
        {
            return Fail(op, PasswordCredentialErrors.Invalid());
        }

        var passwordVerifier = passwordHasher.HashPassword(cmd.NewPassword);
        var result = await credentialStore.ReplacePasswordVerifierAsync(
            cmd.UserId,
            cmd.ExpectedVersion,
            currentVerifier,
            passwordVerifier,
            securityStampGenerator.Generate(),
            now,
            ct);

        return Finish(op, result);
    }

    public async Task<OperationResult> RemovePasswordAsync(
        RemovePasswordCommand cmd,
        CancellationToken ct)
    {
        using var op = metrics.Begin("credential.password.remove");
        var now = DateTimeOffset.UtcNow;

        var user = await userStore.FindByIdAsync(cmd.UserId, ct);
        var userError = ValidateMutableUser(user, cmd.ExpectedVersion);
        if (userError is not null)
        {
            return Fail(op, userError);
        }

        var currentVerifier = await credentialStore.FindPasswordVerifierAsync(cmd.UserId, ct);
        if (currentVerifier is null)
        {
            return Fail(op, PasswordCredentialErrors.NotSet());
        }

        var result = await credentialStore.ReplacePasswordVerifierAsync(
            cmd.UserId,
            cmd.ExpectedVersion,
            currentVerifier,
            passwordVerifier: null,
            securityStampGenerator.Generate(),
            now,
            ct);

        return Finish(op, result);
    }

    public async Task<OperationResult> VerifyPasswordAsync(
        VerifyPasswordCommand cmd,
        CancellationToken ct)
    {
        using var op = metrics.Begin("credential.password.verify");
        var now = DateTimeOffset.UtcNow;

        var validationError = ValidatePassword(cmd.Password, "password");
        if (validationError is not null)
        {
            return Fail(op, validationError);
        }

        var user = await userStore.FindByIdAsync(cmd.UserId, ct);
        if (user is null)
        {
            return Fail(op, IdentityErrors.NotFound());
        }

        if (user.DeletedAt is not null)
        {
            return Fail(op, IdentityErrors.Deleted());
        }

        var currentVerifier = await credentialStore.FindPasswordVerifierAsync(cmd.UserId, ct);
        if (currentVerifier is null)
        {
            return Fail(op, PasswordCredentialErrors.Invalid());
        }

        var verification = passwordHasher.VerifyHashedPassword(
            currentVerifier,
            cmd.Password);
        if (verification == PasswordVerificationResult.Failed)
        {
            return Fail(op, PasswordCredentialErrors.Invalid());
        }

        if (verification == PasswordVerificationResult.SuccessRehashNeeded)
        {
            var passwordVerifier = passwordHasher.HashPassword(cmd.Password);
            var rehashResult = await credentialStore.ReplacePasswordVerifierAsync(
                cmd.UserId,
                user.Version,
                currentVerifier,
                passwordVerifier,
                newSecurityStamp: null,
                now,
                ct);

            if (!rehashResult.IsSuccess
                && !rehashResult.Errors.Any(
                    error => error.Code == IdentityErrorCodes.ConcurrencyConflict))
            {
                return Finish(op, rehashResult);
            }
        }

        op.Success();
        return OperationResultFactory.Success();
    }

    private Error? ValidateMutableUser(
        IdentityUser<TProfile>? user,
        long expectedVersion)
    {
        if (user is null)
        {
            return IdentityErrors.NotFound();
        }

        if (!policy.CanMutate(user.Flags))
        {
            return IdentityErrors.Forbidden(user.Flags);
        }

        if (user.DeletedAt is not null)
        {
            return IdentityErrors.Deleted();
        }

        return user.Version == expectedVersion
            ? null
            : IdentityErrors.Concurrency();
    }

    private static Error? ValidatePassword(string? password, string field)
        => string.IsNullOrEmpty(password)
            ? IdentityErrors.Validation(field, "Password is required.")
            : null;

    private static OperationResult Fail(IIdentityOpScope op, Error error)
    {
        op.Failure(error.Code);
        return OperationResultFactory.Fail(error);
    }

    private static OperationResult Finish(IIdentityOpScope op, OperationResult result)
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
