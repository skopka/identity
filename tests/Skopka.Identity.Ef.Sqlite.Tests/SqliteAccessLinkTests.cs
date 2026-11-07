using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Skopka.Identity.AccessLinks;
using Skopka.Identity.Credentials;
using Skopka.Identity.DeviceAuthorization;
using Skopka.Identity.Ef.Entities;
using Skopka.Identity.Security;
using Skopka.Identity.Sessions;
using Skopka.Identity.Totp;
using Skopka.Identity.Tokens;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Commands;
using Xunit;

namespace Skopka.Identity.Ef.Sqlite.Tests;

public sealed class SqliteAccessLinkTests
{
    [Fact]
    public async Task DeviceApprovalPersistsTrustedSessionContext()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:;Foreign Keys=True");
        await connection.OpenAsync();
        var services = new ServiceCollection();
        services.AddSkopkaIdentity<Profile>().UseSqlite(connection);
        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        var sp = scope.ServiceProvider;
        await sp.GetRequiredService<SqliteIdentityDbContext<Profile>>().Database.MigrateAsync();
        var now = DateTimeOffset.UtcNow;
        var store = sp.GetRequiredService<IDeviceAuthorizationRequestStore<Profile>>();
        var id = Guid.NewGuid();
        var created = await store.CreateAsync(new NewDeviceAuthorizationRequest(id, "device-code", new string('A', 64), "user-code",
            new DeviceAuthorizationMetadata(null, null, null, null, null), now.AddMinutes(5)), now, CancellationToken.None);
        Assert.True(created.IsSuccess);
        var pending = await store.FindByDeviceCodeAsync("device-code", CancellationToken.None);
        var context = new IdentitySessionContext("staff", "password");
        var approved = await store.ApproveAsync(id, pending!.Version, Guid.NewGuid(), "stamp", context, now, CancellationToken.None);
        Assert.True(approved.IsSuccess);
        var loaded = await store.FindByDeviceCodeAsync("device-code", CancellationToken.None);
        Assert.Equal(context, loaded!.Context);
    }

    [Fact]
    public async Task RecoveryIssuanceRevokesCredentialsAndSessionsTogether()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:;Foreign Keys=True");
        await connection.OpenAsync();
        var services = new ServiceCollection();
        services.AddSkopkaIdentity<Profile>().UseSqlite(connection);
        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        var sp = scope.ServiceProvider;
        var db = sp.GetRequiredService<SqliteIdentityDbContext<Profile>>();
        await db.Database.MigrateAsync();
        var user = (await sp.GetRequiredService<IIdentityUserService<Profile>>().CreateAsync(
            new CreateUserCommand<Profile>("staff", null, null, new Profile("A")), CancellationToken.None)).Value;
        db.Credentials.Add(new UserCredentialEntity { UserId = user.Id, PasswordVerifier = "old", UpdatedAt = DateTimeOffset.UtcNow });
        db.TotpFactors.Add(new TotpFactorEntity { UserId = user.Id, EnrollmentId = Guid.NewGuid(), ProtectedSecret = "old-factor", State = TotpFactorState.Enabled, Version = 1, CreatedAt = DateTimeOffset.UtcNow, ModifiedAt = DateTimeOffset.UtcNow });
        await db.SaveChangesAsync();
        var registry = sp.GetRequiredService<IIdentitySessionRegistry<Profile>>();
        var session = await registry.RegisterAsync(new RegisterIdentitySessionCommand(user.Id, user.SecurityStamp), CancellationToken.None);
        Assert.True(session.IsSuccess);
        var service = new IdentityAccessLinkService<Profile>(sp.GetRequiredService<IIdentityAccessLinkStore<Profile>>(),
            sp.GetRequiredService<IIdentityUserStore<Profile>>(), sp.GetRequiredService<IUserOperationPolicy>(),
            new Hasher(), new PasswordPolicyOptions(), [], new Code(), new Protector(), new TotpOptions(),
            sp.GetRequiredService<ISecurityStampGenerator>(), new IdentityAccessLinkOptions());
        var issue = await service.IssueAsync(new(user.Id, user.Version, "staff", true), CancellationToken.None);
        Assert.True(issue.IsSuccess);
        Assert.Null((await db.Credentials.AsNoTracking().SingleAsync()).PasswordVerifier);
        Assert.Empty(await db.TotpFactors.AsNoTracking().ToListAsync());
        Assert.NotNull((await db.Sessions.AsNoTracking().SingleAsync()).RevokedAt);
        Assert.False((await registry.ValidateAsync(new ValidateIdentitySessionCommand(user.Id, session.Value.SessionId), CancellationToken.None)).IsSuccess);
        for (var attempt = 0; attempt < 5; attempt++)
        {
            var enrollment = await service.BeginEnrollmentAsync(new(issue.Value.Token, "staff", null), CancellationToken.None);
            Assert.True(enrollment.IsSuccess);
            Assert.False((await service.CompleteAsync(new(issue.Value.Token, "staff", enrollment.Value.EnrollmentId,
                "bad", "a suitable long password", null), CancellationToken.None)).IsSuccess);
        }
        Assert.False((await service.BeginEnrollmentAsync(new(issue.Value.Token, "staff", null), CancellationToken.None)).IsSuccess);
    }

    [Fact]
    public async Task NewLinkSupersedesAndCompletionAtomicallyInstallsCredentials()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:;Foreign Keys=True");
        await connection.OpenAsync();
        var services = new ServiceCollection();
        services.AddSkopkaIdentity<Profile>().UseSqlite(connection);
        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        var sp = scope.ServiceProvider;
        var db = sp.GetRequiredService<SqliteIdentityDbContext<Profile>>();
        await db.Database.MigrateAsync();
        var user = await sp.GetRequiredService<IIdentityUserService<Profile>>().CreateAsync(
            new CreateUserCommand<Profile>("staff", null, null, new Profile("A")), CancellationToken.None);
        Assert.True(user.IsSuccess);
        db.Credentials.Add(new UserCredentialEntity { UserId = user.Value.Id, PasswordVerifier = "old", UpdatedAt = DateTimeOffset.UtcNow });
        db.TotpFactors.Add(new TotpFactorEntity { UserId = user.Value.Id, EnrollmentId = Guid.NewGuid(), ProtectedSecret = "old-factor", State = TotpFactorState.Enabled, Version = 1, CreatedAt = DateTimeOffset.UtcNow, ModifiedAt = DateTimeOffset.UtcNow });
        await db.SaveChangesAsync();
        var service = new IdentityAccessLinkService<Profile>(sp.GetRequiredService<IIdentityAccessLinkStore<Profile>>(),
            sp.GetRequiredService<IIdentityUserStore<Profile>>(), sp.GetRequiredService<IUserOperationPolicy>(),
            new Hasher(), new PasswordPolicyOptions(), [], new Code(), new Protector(), new TotpOptions(),
            sp.GetRequiredService<ISecurityStampGenerator>(), new IdentityAccessLinkOptions());
        var first = await service.IssueAsync(new(user.Value.Id, user.Value.Version, "staff", false), CancellationToken.None);
        Assert.True(first.IsSuccess);
        Assert.InRange(first.Value.ExpiresAt - DateTimeOffset.UtcNow, TimeSpan.FromDays(7) - TimeSpan.FromMinutes(1), TimeSpan.FromDays(7));
        Assert.Equal(TimeSpan.FromHours(1), new IdentityActionTokenOptions().PasswordResetLifetime);
        var current = await sp.GetRequiredService<IIdentityUserStore<Profile>>().FindByIdAsync(user.Value.Id, CancellationToken.None);
        var second = await service.IssueAsync(new(user.Value.Id, current!.Version, "staff", false), CancellationToken.None);
        Assert.True(second.IsSuccess);
        Assert.Equal("old", (await db.Credentials.AsNoTracking().SingleAsync()).PasswordVerifier);
        Assert.Equal("old-factor", (await db.TotpFactors.AsNoTracking().SingleAsync()).ProtectedSecret);
        Assert.False((await service.InspectAsync(first.Value.Token, "staff", CancellationToken.None)).IsSuccess);
        Assert.False((await service.InspectAsync(second.Value.Token, "main", CancellationToken.None)).IsSuccess);
        var enrollment = await service.BeginEnrollmentAsync(new(second.Value.Token, "staff", null), CancellationToken.None);
        Assert.True(enrollment.IsSuccess);
        var wrong = await service.CompleteAsync(new(second.Value.Token, "staff", enrollment.Value.EnrollmentId,
            "bad", "a suitable long password", null), CancellationToken.None);
        Assert.False(wrong.IsSuccess);
        var restarted = await service.BeginEnrollmentAsync(new(second.Value.Token, "staff", null), CancellationToken.None);
        Assert.True(restarted.IsSuccess);
        Assert.Equal(1, (await db.AccessLinks.AsNoTracking().SingleAsync(x => !x.Consumed)).FailedAttempts);
        var result = await service.CompleteAsync(new(second.Value.Token, "staff", restarted.Value.EnrollmentId,
            "123456", "a suitable long password", null), CancellationToken.None);
        Assert.True(result.IsSuccess);
        Assert.Equal(10, result.Value.RecoveryCodes.Count);
        Assert.False((await service.InspectAsync(second.Value.Token, "staff", CancellationToken.None)).IsSuccess);
        Assert.Equal("hashed", (await db.Credentials.AsNoTracking().SingleAsync()).PasswordVerifier);
        Assert.Equal(TotpFactorState.Enabled, (await db.TotpFactors.AsNoTracking().SingleAsync()).State);
        Assert.Equal(10, await db.TotpRecoveryCodes.CountAsync());
        var expiring = await service.IssueAsync(new(result.Value.User.Id, result.Value.User.Version, "staff", false), CancellationToken.None);
        Assert.True(expiring.IsSuccess);
        var row = await db.AccessLinks.SingleAsync(x => !x.Consumed);
        row.ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1);
        await db.SaveChangesAsync();
        Assert.False((await service.InspectAsync(expiring.Value.Token, "staff", CancellationToken.None)).IsSuccess);
    }

    private sealed class Hasher : IPasswordHasher
    {
        public string HashPassword(string password) => "hashed";
        public PasswordVerificationResult VerifyHashedPassword(string passwordVerifier, string providedPassword) => PasswordVerificationResult.Failed;
    }
    private sealed class Code : ITotpCodeProvider
    {
        public string CreateSecret() => "secret";
        public bool TryMatchCounter(string secret, string response, DateTimeOffset now, long? minimumExclusiveCounter, out long counter)
        { counter = 1; return response == "123456"; }
    }
    private sealed class Protector : ITotpSecretProtector
    {
        public string Protect(string secret) => "protected";
        public bool TryUnprotect(string protectedSecret, out string secret) { secret = "secret"; return true; }
    }
    public sealed record Profile(string Name);
}
