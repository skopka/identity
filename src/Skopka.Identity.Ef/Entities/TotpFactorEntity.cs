using Skopka.Identity.Totp;

namespace Skopka.Identity.Ef.Entities;

public sealed class TotpFactorEntity
{
    public Guid UserId { get; set; }
    public Guid EnrollmentId { get; set; }
    public string ProtectedSecret { get; set; } = null!;
    public TotpFactorState State { get; set; }
    public long? LastAcceptedCounter { get; set; }
    public long Version { get; set; }
    public DateTimeOffset? PendingExpiresAt { get; set; }
    public DateTimeOffset? EnabledAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ModifiedAt { get; set; }

    public AuthUserEntity User { get; set; } = null!;
    public ICollection<TotpRecoveryCodeEntity> RecoveryCodes { get; set; }
        = new List<TotpRecoveryCodeEntity>();
}

public sealed class TotpRecoveryCodeEntity
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public Guid EnrollmentId { get; set; }
    public string CodeHash { get; set; } = null!;
    public long Version { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? UsedAt { get; set; }

    public TotpFactorEntity Factor { get; set; } = null!;
}
