using Microsoft.EntityFrameworkCore;
using Skopka.Abstraction.OperationResult;
using Skopka.Identity.AccessLinks;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.Totp;

namespace Skopka.Identity.Ef;

public sealed class EfIdentityAccessLinkStore<TProfile>(IdentityDbContext<TProfile> db) : IIdentityAccessLinkStore<TProfile>
{
    private static OperationResult Conflict() => OperationResultFactory.Fail(new Error(
        "identity.access_link.invalid", "The access link is invalid or expired.", ErrorType.Validation));

    public async Task<int> PruneAsync(DateTimeOffset expiredBefore, int maxCount, CancellationToken cancellationToken)
    {
        var ids = await db.AccessLinks.AsNoTracking().Where(x => x.ExpiresAt <= expiredBefore)
            .OrderBy(x => x.ExpiresAt).ThenBy(x => x.Id).Take(Math.Clamp(maxCount, 1, 500))
            .Select(x => x.Id).ToListAsync(cancellationToken);
        return await db.AccessLinks.Where(x => ids.Contains(x.Id) && x.ExpiresAt <= expiredBefore)
            .ExecuteDeleteAsync(cancellationToken);
    }

    public async Task<StoredIdentityAccessLink?> FindAsync(Guid id, CancellationToken cancellationToken)
    {
        var x = await db.AccessLinks.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, cancellationToken);
        return x is null ? null : new(x.Id, x.UserId, x.UserVersion, x.Scope, x.TokenHash, x.ExpiresAt,
            x.Version, x.EnrollmentId, x.ProtectedSecret, x.EnrollmentExpiresAt, x.FailedAttempts, x.Consumed);
    }

    public async Task<OperationResult> IssueAsync(StoredIdentityAccessLink link, long expectedUserVersion,
        bool invalidateExisting, string newSecurityStamp, DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (!db.Database.IsRelational()) return Conflict();
        var user = await db.Users.SingleOrDefaultAsync(x => x.Id == link.UserId, cancellationToken);
        if (user is null || user.Version != expectedUserVersion) return Conflict();
        var previous = await db.AccessLinks.Where(x => x.UserId == link.UserId && !x.Consumed).ToListAsync(cancellationToken);
        foreach (var old in previous) { old.Consumed = true; old.Version++; old.ProtectedSecret = null; }
        user.Version++; user.ModifiedAt = now;
        if (invalidateExisting)
        {
            user.SecurityStamp = newSecurityStamp;
            var credential = await db.Credentials.SingleOrDefaultAsync(x => x.UserId == user.Id, cancellationToken);
            if (credential is not null) { credential.PasswordVerifier = null; credential.UpdatedAt = now; }
            var factor = await db.TotpFactors.Include(x => x.RecoveryCodes).SingleOrDefaultAsync(x => x.UserId == user.Id, cancellationToken);
            if (factor is not null) db.TotpFactors.Remove(factor);
            var sessions = await db.Sessions.Where(x => x.UserId == user.Id && x.RevokedAt == null).ToListAsync(cancellationToken);
            foreach (var session in sessions) { session.RevokedAt = now; session.Version++; }
        }
        db.AccessLinks.Add(new IdentityAccessLinkEntity { Id = link.Id, UserId = link.UserId,
            UserVersion = user.Version, Scope = link.Scope, TokenHash = link.TokenHash,
            ExpiresAt = link.ExpiresAt, Version = 1 });
        return await Save(cancellationToken);
    }

    public async Task<OperationResult> BeginEnrollmentAsync(Guid id, long expectedVersion, Guid enrollmentId,
        string protectedSecret, DateTimeOffset expiresAt, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var x = await db.AccessLinks.SingleOrDefaultAsync(x => x.Id == id, cancellationToken);
        if (x is null || x.Version != expectedVersion || x.Consumed || x.ExpiresAt <= now || x.FailedAttempts >= 5) return Conflict();
        x.EnrollmentId = enrollmentId; x.ProtectedSecret = protectedSecret; x.EnrollmentExpiresAt = expiresAt; x.Version++;
        return await Save(cancellationToken);
    }

    public async Task<OperationResult> RecordFailureAsync(Guid id, long expectedVersion, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var x = await db.AccessLinks.SingleOrDefaultAsync(x => x.Id == id, cancellationToken);
        if (x is null || x.Version != expectedVersion || x.Consumed || x.ExpiresAt <= now) return Conflict();
        x.FailedAttempts++; x.Version++;
        return await Save(cancellationToken);
    }

    public async Task<OperationResult> CompleteAsync(StoredIdentityAccessLink link, string passwordVerifier,
        long acceptedCounter, IReadOnlyCollection<string> recoveryCodeHashes, string newSecurityStamp,
        DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (!db.Database.IsRelational()) return Conflict();
        var x = await db.AccessLinks.SingleOrDefaultAsync(x => x.Id == link.Id, cancellationToken);
        var user = await db.Users.SingleOrDefaultAsync(x => x.Id == link.UserId, cancellationToken);
        if (x is null || user is null || x.Version != link.Version || user.Version != link.UserVersion
            || x.Consumed || x.ExpiresAt <= now || x.EnrollmentExpiresAt is null || x.EnrollmentExpiresAt <= now || x.FailedAttempts > 5
            || x.EnrollmentId != link.EnrollmentId || x.ProtectedSecret != link.ProtectedSecret) return Conflict();
        var credential = await db.Credentials.SingleOrDefaultAsync(x => x.UserId == user.Id, cancellationToken);
        if (credential is null) { credential = new UserCredentialEntity { UserId = user.Id }; db.Credentials.Add(credential); }
        credential.PasswordVerifier = passwordVerifier; credential.UpdatedAt = now;
        var factor = await db.TotpFactors.Include(x => x.RecoveryCodes).SingleOrDefaultAsync(x => x.UserId == user.Id, cancellationToken);
        if (factor is null) { factor = new TotpFactorEntity { UserId = user.Id, CreatedAt = now }; db.TotpFactors.Add(factor); }
        else db.TotpRecoveryCodes.RemoveRange(factor.RecoveryCodes);
        factor.EnrollmentId = x.EnrollmentId!.Value; factor.ProtectedSecret = x.ProtectedSecret!;
        factor.State = TotpFactorState.Enabled; factor.LastAcceptedCounter = acceptedCounter;
        factor.PendingExpiresAt = null; factor.EnabledAt = now; factor.ModifiedAt = now; factor.Version++;
        foreach (var hash in recoveryCodeHashes) db.TotpRecoveryCodes.Add(new TotpRecoveryCodeEntity {
            Id = Guid.NewGuid(), UserId = user.Id, EnrollmentId = factor.EnrollmentId, CodeHash = hash, Version = 1, CreatedAt = now });
        x.Consumed = true; x.ProtectedSecret = null; x.Version++;
        user.Version++; user.SecurityStamp = newSecurityStamp; user.ModifiedAt = now;
        return await Save(cancellationToken);
    }

    private async Task<OperationResult> Save(CancellationToken cancellationToken)
    {
        try { await db.SaveChangesAsync(cancellationToken); return OperationResultFactory.Success(); }
        catch (DbUpdateConcurrencyException) { db.ChangeTracker.Clear(); return Conflict(); }
    }
}
