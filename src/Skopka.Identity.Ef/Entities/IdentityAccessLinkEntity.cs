namespace Skopka.Identity.Ef.Entities;

public sealed class IdentityAccessLinkEntity
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public long UserVersion { get; set; }
    public string Scope { get; set; } = null!;
    public string TokenHash { get; set; } = null!;
    public DateTimeOffset ExpiresAt { get; set; }
    public long Version { get; set; }
    public Guid? EnrollmentId { get; set; }
    public string? ProtectedSecret { get; set; }
    public DateTimeOffset? EnrollmentExpiresAt { get; set; }
    public int FailedAttempts { get; set; }
    public bool Consumed { get; set; }
}
