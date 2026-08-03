using Skopka.Identity.Verification;

namespace Skopka.Identity.Ef.Entities;

public sealed class VerificationChallengeEntity
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public string IntentHash { get; set; } = null!;
    public string Purpose { get; set; } = null!;
    public string Binding { get; set; } = null!;
    public string Method { get; set; } = null!;
    public string Verifier { get; set; } = null!;
    public string SecurityStamp { get; set; } = null!;
    public int FailedAttemptCount { get; set; }
    public int MaxAttempts { get; set; }
    public VerificationChallengeState State { get; set; }
    public string? ProofHash { get; set; }
    public DateTimeOffset? ProofExpiresAt { get; set; }
    public long Version { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ModifiedAt { get; set; }
    public DateTimeOffset? VerifiedAt { get; set; }
    public DateTimeOffset? ConsumedAt { get; set; }

    public AuthUserEntity User { get; set; } = null!;
}
