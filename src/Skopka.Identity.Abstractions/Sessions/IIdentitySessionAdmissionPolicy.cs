using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Users;

namespace Skopka.Identity.Sessions;

/// <summary>Operation for which a host checks its current session admission policy.</summary>
public enum IdentitySessionAdmissionOperation { Create, Register, Refresh, Validate }

/// <summary>Trusted, online-validated state supplied to session admission policies.</summary>
public sealed record IdentitySessionAdmissionContext<TProfile>(
    IdentityUser<TProfile> User, IdentitySessionAssurance Assurance,
    IdentitySessionAdmissionOperation Operation, Guid? SessionId, IdentitySessionMetadata? Metadata);

/// <summary>Host policy checked before issuing, rotating, registering or accepting a logical session.</summary>
public interface IIdentitySessionAdmissionPolicy<TProfile>
{
    /// <summary>Returns an expected failure when this session must not be admitted.</summary>
    Task<OperationResult> CheckAsync(IdentitySessionAdmissionContext<TProfile> context, CancellationToken ct);
}
