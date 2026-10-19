using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Credentials;
using Skopka.Identity.ExternalLogins;
using Skopka.Identity.Metrics;
using Skopka.Identity.Security;
using Skopka.Identity.SecurityEvents;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Commands;
using Skopka.Identity.Users.Handles;
using Skopka.Identity.Verification;
using Skopka.Identity.Errors;

namespace Skopka.Identity.Registration;

public sealed class IdentityRegistrationService<TProfile>(
    IIdentityRegistrationStore<TProfile> registrationStore,
    IIdentityNormalizer normalizer,
    IUserOperationPolicy policy,
    ISecurityStampGenerator securityStampGenerator,
    IIdentityMetrics metrics,
    PasswordPolicyOptions passwordPolicyOptions,
    IEnumerable<IPasswordHasher> passwordHashers,
    IEnumerable<IPasswordValidator<TProfile>> passwordValidators,
    IVerificationChallengeStore<TProfile> verificationStore,
    IIdentitySecurityEventObserver? securityEvents = null)
    : IIdentityRegistrationService<TProfile>
{
    private readonly PasswordPolicyOptions passwordPolicy =
        PasswordPolicy.ValidateOptions(passwordPolicyOptions);
    private readonly IPasswordHasher? passwordHasher =
        passwordHashers.FirstOrDefault();
    private readonly IReadOnlyList<IPasswordValidator<TProfile>>
        registeredPasswordValidators = passwordValidators.ToArray();

    public async Task<OperationResult<IdentityUser<TProfile>>> RegisterPasswordAsync(
        RegisterPasswordUserCommand<TProfile> command,
        CancellationToken ct)
    {
        using var op = metrics.Begin("registration.password");
        var now = DateTimeOffset.UtcNow;

        var passwordError = PasswordPolicy.ValidateNewPassword(
            command.Password,
            passwordPolicy);
        if (passwordError is not null)
        {
            return Fail(op, passwordError);
        }

        if (passwordHasher is null)
        {
            return Fail(
                op,
                IdentityRegistrationErrors.PasswordHasherUnavailable());
        }

        var prepared = PrepareUser(command.User, now, out var userError);
        if (userError is not null)
        {
            return Fail(op, userError);
        }

        var proposedUser = ToProposedModel(prepared!.User, now);
        var validationContext = new PasswordValidationContext<TProfile>(
            proposedUser,
            command.Password,
            PasswordMutation.Register);
        foreach (var validator in registeredPasswordValidators)
        {
            var validation = await validator.ValidateAsync(
                validationContext,
                ct);
            if (!validation.IsSuccess)
            {
                return Finish(
                    op,
                    OperationResultFactory.Fail<IdentityUser<TProfile>>(
                        validation.Errors));
            }
        }

        var verifier = passwordHasher.HashPassword(command.Password);
        var result = await registrationStore.CreateWithPasswordAsync(
            prepared.User,
            prepared.Handles,
            verifier,
            now,
            ct);

        if (result.IsSuccess)
        {
            securityEvents.Observe(
                IdentitySecurityEventTypes.PasswordUserRegistered,
                now,
                result.Value.Id);
        }

        return Finish(op, result);
    }

    public async Task<OperationResult<IdentityUser<TProfile>>> RegisterExternalAsync(
        RegisterExternalUserCommand<TProfile> command,
        CancellationToken ct)
    {
        using var op = metrics.Begin("registration.external");
        var now = DateTimeOffset.UtcNow;

        var login = ExternalLoginPolicy.Normalize(
            command.Login,
            out var loginError);
        if (loginError is not null)
        {
            return Fail(op, loginError);
        }

        var prepared = PrepareUser(command.User, now, out var userError);
        if (userError is not null)
        {
            return Fail(op, userError);
        }

        var result = await registrationStore.CreateWithExternalLoginAsync(
            prepared!.User,
            prepared.Handles,
            login!,
            now,
            ct);

        if (result.IsSuccess)
        {
            securityEvents.Observe(
                IdentitySecurityEventTypes.ExternalUserRegistered,
                now,
                result.Value.Id);
        }

        return Finish(op, result);
    }

    public async Task<OperationResult<IdentityUser<TProfile>>> RegisterVerifiedPhoneAsync(
        RegisterVerifiedPhoneUserCommand<TProfile> command,
        CancellationToken ct)
    {
        using var op = metrics.Begin("registration.phone_otp");
        var now = DateTimeOffset.UtcNow;
        if (command.User.Phone is null
            || command.User.UserName is not null
            || command.User.Email is not null)
        {
            return Fail(op, IdentityErrors.Validation(
                "phone", "Phone-only registration requires a phone."));
        }

        var prepared = PrepareUser(command.User, now, out var userError);
        if (userError is not null)
        {
            return Fail(op, userError);
        }

        var challenge = await verificationStore.FindByIdAsync(
            command.Proof.ChallengeId, ct);
        if (challenge is null
            || challenge.UserId != Guid.Empty
            || challenge.Purpose != VerificationPurposes.PhoneSignIn
            || challenge.Binding != command.User.Phone
            || challenge.State != VerificationChallengeState.Verified
            || challenge.ProofExpiresAt <= now
            || challenge.ProofHash is null
            || !VerificationProofCodec.Matches(
                challenge.ProofHash, command.Proof.Token))
        {
            return Fail(op, new Error(
                IdentityErrorCodes.VerificationProofInvalid,
                "Verification proof is invalid or expired.",
                ErrorType.Unauthorized));
        }

        var result = await registrationStore.CreateWithVerifiedPhoneAsync(
            prepared!.User,
            prepared.Handles,
            challenge.Id,
            challenge.Version,
            challenge.ProofHash,
            now,
            ct);
        if (result.IsSuccess)
        {
            securityEvents?.Observe(
                IdentitySecurityEventTypes.PhoneUserRegistered,
                now,
                result.Value.Id);
        }

        return Finish(op, result);
    }

    private PreparedUser? PrepareUser(
        CreateUserCommand<TProfile> command,
        DateTimeOffset now,
        out Error? error)
    {
        if (command.Profile is null)
        {
            error = IdentityErrors.Validation(
                "profile",
                "Profile is required.");
            return null;
        }

        if (!policy.CanMutate(command.Flags))
        {
            error = IdentityErrors.Forbidden(command.Flags);
            return null;
        }

        var user = new NewIdentityUser<TProfile>(
            command.UserName,
            command.Email,
            command.Phone,
            command.Profile,
            command.Flags,
            securityStampGenerator.Generate(),
            Guid.NewGuid());
        var normalizedUserName = normalizer.NormalizeUserName(
            command.UserName);
        var normalizedEmail = normalizer.NormalizeEmail(command.Email);
        var normalizedPhone = normalizer.NormalizePhoneLoginIdentifier(
            command.Phone);
        var loginIdentifierKeys = LoginIdentifierKeyBuilder.Create(
            normalizer,
            command.UserName,
            command.Email,
            command.Phone,
            normalizedUserName,
            normalizedEmail,
            normalizedPhone,
            out var handleError);
        if (handleError is not null)
        {
            error = handleError;
            return null;
        }

        var handles = new NormalizedHandles(
            normalizedUserName,
            normalizedEmail,
            normalizedPhone,
            loginIdentifierKeys);

        error = null;
        return new PreparedUser(user, handles);
    }

    private static IdentityUser<TProfile> ToProposedModel(
        NewIdentityUser<TProfile> user,
        DateTimeOffset now)
        => new(
            user.Id!.Value,
            user.Flags,
            user.UserName,
            user.Email,
            false,
            user.Phone,
            false,
            user.Profile,
            0,
            user.SecurityStamp,
            null,
            null,
            null,
            now,
            now);

    private static OperationResult<IdentityUser<TProfile>> Fail(
        IIdentityOpScope op,
        Error error)
    {
        op.Failure(error.Code);
        return OperationResultFactory.Fail<IdentityUser<TProfile>>(error);
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

    private sealed record PreparedUser(
        NewIdentityUser<TProfile> User,
        NormalizedHandles Handles);
}
