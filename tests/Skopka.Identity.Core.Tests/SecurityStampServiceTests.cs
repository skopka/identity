using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Metrics;
using Skopka.Identity.Security;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Commands;
using Skopka.Identity.Users.Handles;
using Xunit;

namespace Skopka.Identity.Core.Tests;

public sealed class SecurityStampServiceTests
{
    [Fact]
    public async Task UserCreationAssignsGeneratedSecurityStamp()
    {
        var store = new FakeIdentityUserStore(CreateUser());
        var service = new IdentityUserService<TestProfile>(
            store,
            new DefaultIdentityNormalizer(),
            new DefaultUserOperationPolicy(),
            new FakeSecurityStampGenerator(),
            new NoopIdentityMetrics());

        var result = await service.CreateAsync(
            new CreateUserCommand<TestProfile>(
                "alice",
                "alice@example.com",
                null,
                new TestProfile("Alice")),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.NotNull(store.LastNewUser);
        Assert.Equal("NEW-STAMP", store.LastNewUser.SecurityStamp);
        Assert.Equal("NEW-STAMP", result.Value.SecurityStamp);
    }

    [Fact]
    public async Task SoftDeleteRotatesSecurityStamp()
    {
        var store = new FakeIdentityUserStore(CreateUser());
        var service = new IdentityUserService<TestProfile>(
            store,
            new DefaultIdentityNormalizer(),
            new DefaultUserOperationPolicy(),
            new FakeSecurityStampGenerator(),
            new NoopIdentityMetrics());

        var result = await service.DeleteAsync(
            new DeleteUserCommand(store.User.Id, store.User.Version),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal("NEW-STAMP", store.LastStateSecurityStamp);
    }

    [Fact]
    public async Task RotateGeneratesAndPersistsNewSecurityStamp()
    {
        var store = new FakeIdentityUserStore(CreateUser());
        var service = CreateService(store);

        var result = await service.RotateAsync(
            new RotateSecurityStampCommand(store.User.Id, store.User.Version),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal("NEW-STAMP", store.LastSecurityStamp);
        Assert.Equal(store.User.Version, store.LastExpectedVersion);
        Assert.Equal(store.User.Version + 1, result.Value.Version);
        Assert.Equal("NEW-STAMP", result.Value.SecurityStamp);
    }

    [Fact]
    public async Task RotateChecksExpectedVersion()
    {
        var store = new FakeIdentityUserStore(CreateUser());
        var service = CreateService(store);

        var result = await service.RotateAsync(
            new RotateSecurityStampCommand(
                store.User.Id,
                store.User.Version + 1),
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Equal(0, store.UpdateCalls);
    }

    [Fact]
    public async Task ValidateAcceptsCurrentStamp()
    {
        var store = new FakeIdentityUserStore(CreateUser());
        var service = CreateService(store);

        Assert.True(
            await service.ValidateAsync(
                store.User.Id,
                store.User.SecurityStamp,
                CancellationToken.None));
        Assert.False(
            await service.ValidateAsync(
                store.User.Id,
                "WRONG-STAMP",
                CancellationToken.None));
    }

    [Fact]
    public async Task ValidateRejectsDeletedAndActivelyBlockedUsers()
    {
        var deleted = new FakeIdentityUserStore(
            CreateUser() with { DeletedAt = DateTimeOffset.UtcNow });
        var blocked = new FakeIdentityUserStore(
            CreateUser() with
            {
                BlockedAt = DateTimeOffset.UtcNow.AddMinutes(-1),
                BlockedUntil = DateTimeOffset.UtcNow.AddMinutes(10)
            });

        Assert.False(
            await CreateService(deleted).ValidateAsync(
                deleted.User.Id,
                deleted.User.SecurityStamp,
                CancellationToken.None));
        Assert.False(
            await CreateService(blocked).ValidateAsync(
                blocked.User.Id,
                blocked.User.SecurityStamp,
                CancellationToken.None));
    }

    [Fact]
    public async Task ValidateAcceptsExpiredTemporaryBlock()
    {
        var store = new FakeIdentityUserStore(
            CreateUser() with
            {
                BlockedAt = DateTimeOffset.UtcNow.AddMinutes(-10),
                BlockedUntil = DateTimeOffset.UtcNow.AddMinutes(-1)
            });

        Assert.True(
            await CreateService(store).ValidateAsync(
                store.User.Id,
                store.User.SecurityStamp,
                CancellationToken.None));
    }

    [Fact]
    public void DefaultGeneratorCreatesDistinct256BitStamps()
    {
        var generator = new DefaultSecurityStampGenerator();

        var first = generator.Generate();
        var second = generator.Generate();

        Assert.Equal(64, first.Length);
        Assert.Equal(64, second.Length);
        Assert.NotEqual(first, second);
    }

    private static SecurityStampService<TestProfile> CreateService(
        FakeIdentityUserStore store)
        => new(
            store,
            new FakeSecurityStampGenerator(),
            new DefaultUserOperationPolicy(),
            new NoopIdentityMetrics());

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
            3,
            "CURRENT-STAMP",
            null,
            null,
            null,
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(-1));

    private sealed class FakeSecurityStampGenerator : ISecurityStampGenerator
    {
        public string Generate() => "NEW-STAMP";
    }

    private sealed class FakeIdentityUserStore(IdentityUser<TestProfile> user)
        : IIdentityUserStore<TestProfile>
    {
        public IdentityUser<TestProfile> User { get; } = user;
        public int UpdateCalls { get; private set; }
        public long LastExpectedVersion { get; private set; }
        public string? LastSecurityStamp { get; private set; }
        public NewIdentityUser<TestProfile>? LastNewUser { get; private set; }
        public string? LastStateSecurityStamp { get; private set; }

        public Task<IdentityUser<TestProfile>?> FindByIdAsync(
            Guid id,
            CancellationToken ct)
            => Task.FromResult(id == User.Id ? User : null);

        public Task<OperationResult<IdentityUser<TestProfile>>> UpdateSecurityStampAsync(
            Guid userId,
            long expectedVersion,
            string securityStamp,
            DateTimeOffset now,
            CancellationToken ct)
        {
            UpdateCalls++;
            LastExpectedVersion = expectedVersion;
            LastSecurityStamp = securityStamp;
            return Task.FromResult(
                OperationResultFactory.Success(
                    User with
                    {
                        Version = User.Version + 1,
                        SecurityStamp = securityStamp,
                        ModifiedAt = now
                    }));
        }

        public Task<OperationResult<IdentityUser<TestProfile>>> CreateAsync(
            NewIdentityUser<TestProfile> newUser,
            NormalizedHandles handles,
            DateTimeOffset now,
            CancellationToken ct)
        {
            LastNewUser = newUser;
            return Task.FromResult(
                OperationResultFactory.Success(
                    new IdentityUser<TestProfile>(
                        Guid.NewGuid(),
                        newUser.Flags,
                        newUser.UserName,
                        newUser.Email,
                        false,
                        newUser.Phone,
                        false,
                        newUser.Profile,
                        1,
                        newUser.SecurityStamp,
                        null,
                        null,
                        null,
                        now,
                        now)));
        }

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

        public Task<OperationResult> UpdateStateAsync(
            Guid userId,
            long expectedVersion,
            DateTimeOffset? deletedAt,
            DateTimeOffset? blockedAt,
            DateTimeOffset? blockedUntil,
            string? newSecurityStamp,
            DateTimeOffset now,
            CancellationToken ct)
        {
            LastStateSecurityStamp = newSecurityStamp;
            return Task.FromResult(OperationResultFactory.Success());
        }
    }

    public sealed record TestProfile(string DisplayName);
}
