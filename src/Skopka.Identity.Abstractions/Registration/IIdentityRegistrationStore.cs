using Skopka.Identity.Errors;
using Skopka.Abstraction.OperationResult;
using Skopka.Identity.ExternalLogins;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Handles;

namespace Skopka.Identity.Registration;

public interface IIdentityRegistrationStore<TProfile>
{
    /// <summary>Atomically consumes the proof and updates the user's confirmed phone.</summary>
    /// <remarks>Implementations must recheck proof state, expiry, binding and version, and enforce user version and handle uniqueness.</remarks>
    Task<OperationResult<IdentityUser<TProfile>>> BindVerifiedPhoneAsync(
        Guid userId, long expectedVersion, UpdatedHandles handles,
        Guid challengeId, long challengeVersion, string proofHash,
        DateTimeOffset now, CancellationToken ct)
        => Task.FromResult(OperationResultFactory.Fail<IdentityUser<TProfile>>(new Error(
            IdentityErrorCodes.PhoneBindingUnavailable, "Phone binding is unavailable.", ErrorType.Forbidden)));

    Task<OperationResult<IdentityUser<TProfile>>> CreateWithPasswordAsync(
        NewIdentityUser<TProfile> user,
        NormalizedHandles handles,
        string passwordVerifier,
        DateTimeOffset now,
        CancellationToken ct);

    Task<OperationResult<IdentityUser<TProfile>>> CreateWithExternalLoginAsync(
        NewIdentityUser<TProfile> user,
        NormalizedHandles handles,
        ExternalLoginKey login,
        DateTimeOffset now,
        CancellationToken ct);

    Task<OperationResult<IdentityUser<TProfile>>> CreateWithVerifiedPhoneAsync(
        NewIdentityUser<TProfile> user,
        NormalizedHandles handles,
        Guid challengeId,
        long challengeVersion,
        string proofHash,
        DateTimeOffset now,
        CancellationToken ct);
}
