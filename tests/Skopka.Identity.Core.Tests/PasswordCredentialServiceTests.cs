using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Credentials;
using Skopka.Identity.Errors;
using Skopka.Identity.Metrics;
using Skopka.Identity.Security;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Handles;
using Xunit;

namespace Skopka.Identity.Core.Tests;

public sealed class PasswordCredentialServiceTests
{
    [Fact]
    public async Task SetPasswordHashesAndPersistsVerifier()
    {
        var fixture = new Fixture();

        var result = await fixture.Service.SetPasswordAsync(
            new SetPasswordCommand(fixture.User.Id, fixture.User.Version, "new password"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal("hash:new password", fixture.CredentialStore.PasswordVerifier);
        Assert.Equal(fixture.User.Version, fixture.CredentialStore.LastExpectedVersion);
        Assert.Null(fixture.CredentialStore.LastExpectedPasswordVerifier);
        Assert.Equal("NEW-STAMP", fixture.CredentialStore.LastNewSecurityStamp);
    }

    [Fact]
    public async Task SetPasswordRejectsExistingCredential()
    {
        var fixture = new Fixture(passwordVerifier: "hash:existing");

        var result = await fixture.Service.SetPasswordAsync(
            new SetPasswordCommand(fixture.User.Id, fixture.User.Version, "new password"),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.PasswordAlreadySet);
        Assert.Equal(0, fixture.CredentialStore.ReplaceCalls);
    }

    [Fact]
    public async Task ChangePasswordRequiresCurrentPassword()
    {
        var fixture = new Fixture(passwordVerifier: "hash:current");

        var result = await fixture.Service.ChangePasswordAsync(
            new ChangePasswordCommand(
                fixture.User.Id,
                fixture.User.Version,
                "wrong",
                "new password"),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.InvalidPassword);
        Assert.Equal(0, fixture.CredentialStore.ReplaceCalls);
    }

    [Fact]
    public async Task ChangePasswordReplacesVerifiedCredential()
    {
        var fixture = new Fixture(passwordVerifier: "hash:current");

        var result = await fixture.Service.ChangePasswordAsync(
            new ChangePasswordCommand(
                fixture.User.Id,
                fixture.User.Version,
                "current",
                "new password"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal("hash:current", fixture.CredentialStore.LastExpectedPasswordVerifier);
        Assert.Equal("hash:new password", fixture.CredentialStore.PasswordVerifier);
        Assert.Equal("NEW-STAMP", fixture.CredentialStore.LastNewSecurityStamp);
    }

    [Fact]
    public async Task RemovePasswordClearsExistingCredential()
    {
        var fixture = new Fixture(passwordVerifier: "hash:current");

        var result = await fixture.Service.RemovePasswordAsync(
            new RemovePasswordCommand(fixture.User.Id, fixture.User.Version),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Null(fixture.CredentialStore.PasswordVerifier);
        Assert.Equal("hash:current", fixture.CredentialStore.LastExpectedPasswordVerifier);
        Assert.Equal("NEW-STAMP", fixture.CredentialStore.LastNewSecurityStamp);
    }

    [Fact]
    public async Task VerifyPasswordRehashesOutdatedVerifier()
    {
        var fixture = new Fixture(passwordVerifier: "legacy");
        fixture.Hasher.LegacyVerifierNeedsRehash = true;

        var result = await fixture.Service.VerifyPasswordAsync(
            new VerifyPasswordCommand(fixture.User.Id, "current"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal("legacy", fixture.CredentialStore.LastExpectedPasswordVerifier);
        Assert.Equal("hash:current", fixture.CredentialStore.PasswordVerifier);
        Assert.Null(fixture.CredentialStore.LastNewSecurityStamp);
    }

    [Fact]
    public async Task VerifyPasswordReportsInvalidPassword()
    {
        var fixture = new Fixture(passwordVerifier: "hash:current");

        var result = await fixture.Service.VerifyPasswordAsync(
            new VerifyPasswordCommand(fixture.User.Id, "wrong"),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.InvalidPassword);
        Assert.Equal(0, fixture.CredentialStore.ReplaceCalls);
    }

    [Theory]
    [InlineData(UserFlags.System)]
    [InlineData(UserFlags.Protected)]
    public async Task PasswordMutationRejectsProtectedUserFlags(UserFlags flags)
    {
        var fixture = new Fixture(flags: flags);

        var result = await fixture.Service.SetPasswordAsync(
            new SetPasswordCommand(fixture.User.Id, fixture.User.Version, "new password"),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.Forbidden);
        Assert.Equal(0, fixture.CredentialStore.ReplaceCalls);
    }

    [Fact]
    public async Task PasswordMutationChecksExpectedVersion()
    {
        var fixture = new Fixture();

        var result = await fixture.Service.SetPasswordAsync(
            new SetPasswordCommand(
                fixture.User.Id,
                fixture.User.Version + 1,
                "new password"),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.ConcurrencyConflict);
        Assert.Equal(0, fixture.CredentialStore.ReplaceCalls);
    }

    private static void AssertError(OperationResult result, string errorCode)
    {
        Assert.False(result.IsSuccess);
        Assert.Contains(result.Errors, error => error.Code == errorCode);
    }

    private sealed class Fixture
    {
        public Fixture(
            string? passwordVerifier = null,
            UserFlags flags = UserFlags.None)
        {
            User = new IdentityUser<TestProfile>(
                Guid.NewGuid(),
                flags,
                "alice",
                "alice@example.com",
                true,
                null,
                false,
                new TestProfile("Alice"),
                3,
                "OLD-STAMP",
                null,
                null,
                null,
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddDays(-1));

            CredentialStore = new FakePasswordCredentialStore(passwordVerifier);
            Hasher = new FakePasswordHasher();
            Service = new PasswordCredentialService<TestProfile>(
                new FakeIdentityUserStore(User),
                CredentialStore,
                Hasher,
                new FakeSecurityStampGenerator(),
                new DefaultUserOperationPolicy(),
                new NoopIdentityMetrics(),
                []);
        }

        public IdentityUser<TestProfile> User { get; }
        public FakePasswordCredentialStore CredentialStore { get; }
        public FakePasswordHasher Hasher { get; }
        public PasswordCredentialService<TestProfile> Service { get; }
    }

    private sealed class FakePasswordCredentialStore(string? passwordVerifier)
        : IPasswordCredentialStore<TestProfile>
    {
        public string? PasswordVerifier { get; private set; } = passwordVerifier;
        public string? LastExpectedPasswordVerifier { get; private set; }
        public long LastExpectedVersion { get; private set; }
        public string? LastNewSecurityStamp { get; private set; }
        public int ReplaceCalls { get; private set; }

        public Task<string?> FindPasswordVerifierAsync(
            Guid userId,
            CancellationToken ct)
            => Task.FromResult(PasswordVerifier);

        public Task<OperationResult> ReplacePasswordVerifierAsync(
            Guid userId,
            long expectedVersion,
            string? expectedPasswordVerifier,
            string? newPasswordVerifier,
            string? newSecurityStamp,
            DateTimeOffset now,
            CancellationToken ct)
        {
            ReplaceCalls++;
            LastExpectedVersion = expectedVersion;
            LastExpectedPasswordVerifier = expectedPasswordVerifier;
            LastNewSecurityStamp = newSecurityStamp;
            PasswordVerifier = newPasswordVerifier;
            return Task.FromResult(OperationResultFactory.Success());
        }
    }

    private sealed class FakeSecurityStampGenerator : ISecurityStampGenerator
    {
        public string Generate() => "NEW-STAMP";
    }

    private sealed class FakePasswordHasher : IPasswordHasher
    {
        public bool LegacyVerifierNeedsRehash { get; set; }

        public string HashPassword(string password) => $"hash:{password}";

        public PasswordVerificationResult VerifyHashedPassword(
            string passwordVerifier,
            string providedPassword)
        {
            if (passwordVerifier == "legacy"
                && providedPassword == "current"
                && LegacyVerifierNeedsRehash)
            {
                return PasswordVerificationResult.SuccessRehashNeeded;
            }

            return passwordVerifier == $"hash:{providedPassword}"
                ? PasswordVerificationResult.Success
                : PasswordVerificationResult.Failed;
        }
    }

    private sealed class FakeIdentityUserStore(IdentityUser<TestProfile> user)
        : IIdentityUserStore<TestProfile>
    {
        public Task<IdentityUser<TestProfile>?> FindByIdAsync(
            Guid id,
            CancellationToken ct)
            => Task.FromResult(id == user.Id ? user : null);

        public Task<OperationResult<IdentityUser<TestProfile>>> CreateAsync(
            NewIdentityUser<TestProfile> newUser,
            NormalizedHandles handles,
            DateTimeOffset now,
            CancellationToken ct)
            => throw new NotSupportedException();

        public Task<OperationResult<IdentityUser<TestProfile>>> UpdateHandlesAsync(
            Guid userId,
            long expectedVersion,
            UpdatedHandles updated,
            DateTimeOffset now,
            CancellationToken ct)
            => throw new NotSupportedException();

        public Task<OperationResult<IdentityUser<TestProfile>>> UpdateProfileAsync(
            Guid userId,
            long expectedVersion,
            TestProfile profile,
            DateTimeOffset now,
            CancellationToken ct)
            => throw new NotSupportedException();

        public Task<OperationResult<IdentityUser<TestProfile>>> UpdateSecurityStampAsync(
            Guid userId,
            long expectedVersion,
            string securityStamp,
            DateTimeOffset now,
            CancellationToken ct)
            => throw new NotSupportedException();

        public Task<OperationResult> UpdateStateAsync(
            Guid userId,
            long expectedVersion,
            DateTimeOffset? deletedAt,
            DateTimeOffset? blockedAt,
            DateTimeOffset? blockedUntil,
            string? newSecurityStamp,
            DateTimeOffset now,
            CancellationToken ct)
            => throw new NotSupportedException();
    }

    public sealed record TestProfile(string DisplayName);
}
