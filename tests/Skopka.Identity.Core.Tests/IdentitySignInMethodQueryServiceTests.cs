using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Credentials;
using Skopka.Identity.Errors;
using Skopka.Identity.ExternalLogins;
using Skopka.Identity.Metrics;
using Skopka.Identity.SignInMethods;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Handles;
using Xunit;

namespace Skopka.Identity.Core.Tests;

public sealed class IdentitySignInMethodQueryServiceTests
{
    [Fact]
    public async Task GetReturnsCurrentVersionPasswordPresenceAndExternalLogins()
    {
        var user = CreateUser();
        var mutableLogins = new List<ExternalLoginInfo>
        {
            new(
                user.Id,
                new ExternalLoginKey("GITHUB", "Case-Sensitive-Subject"),
                DateTimeOffset.UtcNow.AddHours(-2)),
            new(
                user.Id,
                new ExternalLoginKey("CORPORATE", "employee-42"),
                DateTimeOffset.UtcNow.AddHours(-1)),
        };
        var userStore = new FakeUserStore(user);
        var credentialStore = new FakePasswordCredentialStore("opaque-verifier");
        var externalLoginStore = new FakeExternalLoginStore(mutableLogins);
        var service = CreateService(userStore, credentialStore, externalLoginStore);

        var result = await service.GetAsync(user.Id, CancellationToken.None);
        mutableLogins.Clear();

        Assert.True(result.IsSuccess);
        Assert.Equal(user.Id, result.Value.UserId);
        Assert.Equal(user.Version, result.Value.Version);
        Assert.True(result.Value.HasPassword);
        Assert.Collection(
            result.Value.ExternalLogins,
            login => Assert.Equal(
                new ExternalLoginKey("GITHUB", "Case-Sensitive-Subject"),
                login.Login),
            login => Assert.Equal(
                new ExternalLoginKey("CORPORATE", "employee-42"),
                login.Login));
        Assert.Equal(user.Id, credentialStore.LastUserId);
        Assert.Equal(user.Id, externalLoginStore.LastUserId);
    }

    [Fact]
    public async Task GetReportsPasswordAsAbsentWhenVerifierIsMissing()
    {
        var user = CreateUser();
        var service = CreateService(
            new FakeUserStore(user),
            new FakePasswordCredentialStore(null),
            new FakeExternalLoginStore([]));

        var result = await service.GetAsync(user.Id, CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.False(result.Value.HasPassword);
        Assert.Empty(result.Value.ExternalLogins);
    }

    [Fact]
    public async Task GetReturnsNotFoundWithoutReadingSignInMethods()
    {
        var credentialStore = new FakePasswordCredentialStore("opaque-verifier");
        var externalLoginStore = new FakeExternalLoginStore([]);
        var service = CreateService(
            new FakeUserStore(null),
            credentialStore,
            externalLoginStore);

        var result = await service.GetAsync(Guid.NewGuid(), CancellationToken.None);

        AssertError(result, IdentityErrorCodes.UserNotFound);
        Assert.Equal(0, credentialStore.Calls);
        Assert.Equal(0, externalLoginStore.Calls);
    }

    [Fact]
    public async Task GetReturnsDeletedWithoutReadingSignInMethods()
    {
        var user = CreateUser() with { DeletedAt = DateTimeOffset.UtcNow };
        var credentialStore = new FakePasswordCredentialStore("opaque-verifier");
        var externalLoginStore = new FakeExternalLoginStore([]);
        var service = CreateService(
            new FakeUserStore(user),
            credentialStore,
            externalLoginStore);

        var result = await service.GetAsync(user.Id, CancellationToken.None);

        AssertError(result, IdentityErrorCodes.UserDeleted);
        Assert.Equal(0, credentialStore.Calls);
        Assert.Equal(0, externalLoginStore.Calls);
    }

    [Fact]
    public async Task GetRejectsEmptyUserIdWithoutReadingStores()
    {
        var userStore = new FakeUserStore(CreateUser());
        var credentialStore = new FakePasswordCredentialStore("opaque-verifier");
        var externalLoginStore = new FakeExternalLoginStore([]);
        var service = CreateService(userStore, credentialStore, externalLoginStore);

        var result = await service.GetAsync(Guid.Empty, CancellationToken.None);

        AssertError(result, IdentityErrorCodes.Validation);
        Assert.Equal(0, userStore.Calls);
        Assert.Equal(0, credentialStore.Calls);
        Assert.Equal(0, externalLoginStore.Calls);
    }

    private static IdentitySignInMethodQueryService<TestProfile> CreateService(
        FakeUserStore userStore,
        FakePasswordCredentialStore credentialStore,
        FakeExternalLoginStore externalLoginStore)
        => new(
            userStore,
            credentialStore,
            externalLoginStore,
            new NoopIdentityMetrics());

    private static void AssertError(
        OperationResult<SignInMethodSnapshot> result,
        string code)
    {
        Assert.False(result.IsSuccess);
        Assert.Contains(result.Errors, error => error.Code == code);
    }

    private sealed class FakeUserStore(IdentityUser<TestProfile>? user)
        : IIdentityUserStore<TestProfile>
    {
        public int Calls { get; private set; }

        public Task<IdentityUser<TestProfile>?> FindByIdAsync(
            Guid id,
            CancellationToken ct)
        {
            Calls++;
            return Task.FromResult(user?.Id == id ? user : null);
        }

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

    private sealed class FakePasswordCredentialStore(string? verifier)
        : IPasswordCredentialStore<TestProfile>
    {
        public int Calls { get; private set; }
        public Guid? LastUserId { get; private set; }

        public Task<string?> FindPasswordVerifierAsync(
            Guid userId,
            CancellationToken ct)
        {
            Calls++;
            LastUserId = userId;
            return Task.FromResult(verifier);
        }

        public Task<OperationResult> ReplacePasswordVerifierAsync(
            Guid userId,
            long expectedVersion,
            string? expectedPasswordVerifier,
            string? passwordVerifier,
            string? newSecurityStamp,
            DateTimeOffset now,
            CancellationToken ct)
            => throw new NotSupportedException();
    }

    private sealed class FakeExternalLoginStore(
        IReadOnlyList<ExternalLoginInfo> externalLogins)
        : IExternalLoginStore<TestProfile>
    {
        public int Calls { get; private set; }
        public Guid? LastUserId { get; private set; }

        public Task<IdentityUser<TestProfile>?> FindActiveUserAsync(
            ExternalLoginKey login,
            CancellationToken ct)
            => throw new NotSupportedException();

        public Task<IReadOnlyList<ExternalLoginInfo>> ListAsync(
            Guid userId,
            CancellationToken ct)
        {
            Calls++;
            LastUserId = userId;
            return Task.FromResult(externalLogins);
        }

        public Task<OperationResult<IdentityUser<TestProfile>>> LinkAsync(
            Guid userId,
            long expectedVersion,
            ExternalLoginKey login,
            string newSecurityStamp,
            DateTimeOffset now,
            CancellationToken ct)
            => throw new NotSupportedException();

        public Task<OperationResult<IdentityUser<TestProfile>>> UnlinkAsync(
            Guid userId,
            long expectedVersion,
            ExternalLoginKey login,
            string newSecurityStamp,
            DateTimeOffset now,
            CancellationToken ct)
            => throw new NotSupportedException();
    }

    private static IdentityUser<TestProfile> CreateUser()
        => new(
            Guid.NewGuid(),
            UserFlags.None,
            "alice",
            "alice@example.com",
            true,
            null,
            false,
            new TestProfile("Alice"),
            7,
            "CURRENT-STAMP",
            null,
            null,
            null,
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(-1));

    public sealed record TestProfile(string DisplayName);
}
