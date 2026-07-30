using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;
using Skopka.Identity.ExternalLogins;
using Skopka.Identity.Metrics;
using Skopka.Identity.Security;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Handles;
using Xunit;

namespace Skopka.Identity.Core.Tests;

public sealed class ExternalLoginServiceTests
{
    [Fact]
    public async Task ResolveNormalizesProviderAndPreservesSubject()
    {
        var fixture = new Fixture();
        fixture.LoginStore.ResolvedUser = fixture.UserStore.User;

        var result = await fixture.Service.ResolveAsync(
            new ExternalLoginKey("  Google ", "Case-Sensitive-Subject"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal(
            new ExternalLoginKey("GOOGLE", "Case-Sensitive-Subject"),
            fixture.LoginStore.LastLogin);
    }

    [Fact]
    public async Task ResolveMissingLoginReturnsStableError()
    {
        var fixture = new Fixture();

        var result = await fixture.Service.ResolveAsync(
            new ExternalLoginKey("google", "missing"),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.ExternalLoginNotFound);
    }

    [Fact]
    public async Task LinkRotatesSecurityStampAndUsesExpectedVersion()
    {
        var fixture = new Fixture();

        var result = await fixture.Service.LinkAsync(
            new LinkExternalLoginCommand(
                fixture.UserStore.User.Id,
                fixture.UserStore.User.Version,
                new ExternalLoginKey("github", "123")),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal("NEW-STAMP", fixture.LoginStore.LastSecurityStamp);
        Assert.Equal(fixture.UserStore.User.Version, fixture.LoginStore.LastExpectedVersion);
        Assert.Equal(new ExternalLoginKey("GITHUB", "123"), fixture.LoginStore.LastLogin);
    }

    [Fact]
    public async Task LinkRejectsProtectedUserBeforeStoreMutation()
    {
        var fixture = new Fixture();
        fixture.UserStore.User = fixture.UserStore.User with
        {
            Flags = UserFlags.Protected,
        };

        var result = await fixture.Service.LinkAsync(
            new LinkExternalLoginCommand(
                fixture.UserStore.User.Id,
                fixture.UserStore.User.Version,
                new ExternalLoginKey("github", "123")),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.Forbidden);
        Assert.Null(fixture.LoginStore.LastLogin);
    }

    [Fact]
    public async Task UnlinkRejectsStaleVersionBeforeStoreMutation()
    {
        var fixture = new Fixture();

        var result = await fixture.Service.UnlinkAsync(
            new UnlinkExternalLoginCommand(
                fixture.UserStore.User.Id,
                fixture.UserStore.User.Version + 1,
                new ExternalLoginKey("github", "123")),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.ConcurrencyConflict);
        Assert.Null(fixture.LoginStore.LastLogin);
    }

    [Fact]
    public async Task ListRejectsDeletedUser()
    {
        var fixture = new Fixture();
        fixture.UserStore.User = fixture.UserStore.User with
        {
            DeletedAt = DateTimeOffset.UtcNow,
        };

        var result = await fixture.Service.ListAsync(
            fixture.UserStore.User.Id,
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.UserDeleted);
    }

    private static void AssertError<T>(
        OperationResult<T> result,
        string code)
    {
        Assert.False(result.IsSuccess);
        Assert.Contains(result.Errors, error => error.Code == code);
    }

    private sealed class Fixture
    {
        public Fixture()
        {
            UserStore = new FakeUserStore(CreateUser());
            LoginStore = new FakeExternalLoginStore();
            Service = new ExternalLoginService<TestProfile>(
                UserStore,
                LoginStore,
                new DefaultUserOperationPolicy(),
                new FakeSecurityStampGenerator(),
                new NoopIdentityMetrics());
        }

        public FakeUserStore UserStore { get; }
        public FakeExternalLoginStore LoginStore { get; }
        public ExternalLoginService<TestProfile> Service { get; }
    }

    private sealed class FakeExternalLoginStore
        : IExternalLoginStore<TestProfile>
    {
        public IdentityUser<TestProfile>? ResolvedUser { get; set; }
        public ExternalLoginKey? LastLogin { get; private set; }
        public string? LastSecurityStamp { get; private set; }
        public long? LastExpectedVersion { get; private set; }

        public Task<IdentityUser<TestProfile>?> FindActiveUserAsync(
            ExternalLoginKey login,
            CancellationToken ct)
        {
            LastLogin = login;
            return Task.FromResult(ResolvedUser);
        }

        public Task<IReadOnlyList<ExternalLoginInfo>> ListAsync(
            Guid userId,
            CancellationToken ct)
            => Task.FromResult<IReadOnlyList<ExternalLoginInfo>>([]);

        public Task<OperationResult<IdentityUser<TestProfile>>> LinkAsync(
            Guid userId,
            long expectedVersion,
            ExternalLoginKey login,
            string newSecurityStamp,
            DateTimeOffset now,
            CancellationToken ct)
            => MutateAsync(
                userId,
                expectedVersion,
                login,
                newSecurityStamp);

        public Task<OperationResult<IdentityUser<TestProfile>>> UnlinkAsync(
            Guid userId,
            long expectedVersion,
            ExternalLoginKey login,
            string newSecurityStamp,
            DateTimeOffset now,
            CancellationToken ct)
            => MutateAsync(
                userId,
                expectedVersion,
                login,
                newSecurityStamp);

        private Task<OperationResult<IdentityUser<TestProfile>>> MutateAsync(
            Guid userId,
            long expectedVersion,
            ExternalLoginKey login,
            string newSecurityStamp)
        {
            LastLogin = login;
            LastSecurityStamp = newSecurityStamp;
            LastExpectedVersion = expectedVersion;
            var user = CreateUser() with
            {
                Id = userId,
                Version = expectedVersion + 1,
                SecurityStamp = newSecurityStamp,
            };
            return Task.FromResult(OperationResultFactory.Success(user));
        }
    }

    private sealed class FakeUserStore(IdentityUser<TestProfile> user)
        : IIdentityUserStore<TestProfile>
    {
        public IdentityUser<TestProfile> User { get; set; } = user;

        public Task<IdentityUser<TestProfile>?> FindByIdAsync(
            Guid id,
            CancellationToken ct)
            => Task.FromResult(id == User.Id ? User : null);

        public Task<OperationResult<IdentityUser<TestProfile>>> CreateAsync(
            NewIdentityUser<TestProfile> user,
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

    private sealed class FakeSecurityStampGenerator : ISecurityStampGenerator
    {
        public string Generate() => "NEW-STAMP";
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
            1,
            "CURRENT-STAMP",
            null,
            null,
            null,
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(-1));

    public sealed record TestProfile(string DisplayName);
}
