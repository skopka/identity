using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Authentication;
using Skopka.Identity.Errors;
using Skopka.Identity.Metrics;
using Skopka.Identity.Users;
using Xunit;

namespace Skopka.Identity.Core.Tests;

public sealed class IdentityUserLookupServiceTests
{
    [Fact]
    public async Task FindsActiveUserByNormalizedEmail()
    {
        var user = CreateUser();
        var store = new FakeLookupStore(user);
        var service = new IdentityUserLookupService<TestProfile>(
            store,
            new DefaultIdentityNormalizer(),
            new NoopIdentityMetrics());

        var result = await service.FindActiveByEmailAsync(
            " Alice@Example.com ",
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal(user, result.Value);
        Assert.Equal(
            "ALICE@EXAMPLE.COM",
            store.NormalizedEmail);
    }

    [Fact]
    public async Task UnknownEmailReturnsNotFound()
    {
        var service = new IdentityUserLookupService<TestProfile>(
            new FakeLookupStore(null),
            new DefaultIdentityNormalizer(),
            new NoopIdentityMetrics());

        var result = await service.FindActiveByEmailAsync(
            "unknown@example.com",
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Errors,
            error => error.Code == IdentityErrorCodes.UserNotFound);
    }

    [Fact]
    public async Task EmptyEmailReturnsValidationWithoutStoreCall()
    {
        var store = new FakeLookupStore(CreateUser());
        var service = new IdentityUserLookupService<TestProfile>(
            store,
            new DefaultIdentityNormalizer(),
            new NoopIdentityMetrics());

        var result = await service.FindActiveByEmailAsync(
            " ",
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Errors,
            error => error.Code == IdentityErrorCodes.Validation);
        Assert.Null(store.NormalizedEmail);
    }

    [Fact]
    public async Task FindsActiveUserByNormalizedPhone()
    {
        var user = CreateUser();
        var store = new FakeLookupStore(user);
        var service = new IdentityUserLookupService<TestProfile>(
            store,
            new DefaultIdentityNormalizer(),
            new NoopIdentityMetrics());

        var result = await service.FindActiveByPhoneAsync(
            "+1 (234) 567-8901",
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal(user, result.Value);
        Assert.Equal("12345678901", store.NormalizedPhone);
    }

    [Fact]
    public async Task UnknownPhoneReturnsNotFound()
    {
        var service = new IdentityUserLookupService<TestProfile>(
            new FakeLookupStore(null),
            new DefaultIdentityNormalizer(),
            new NoopIdentityMetrics());

        var result = await service.FindActiveByPhoneAsync(
            "+1 (234) 567-8901",
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Errors,
            error => error.Code == IdentityErrorCodes.UserNotFound);
    }

    [Fact]
    public async Task InvalidPhoneReturnsValidationWithoutStoreCall()
    {
        var store = new FakeLookupStore(CreateUser());
        var service = new IdentityUserLookupService<TestProfile>(
            store,
            new DefaultIdentityNormalizer(),
            new NoopIdentityMetrics());

        var result = await service.FindActiveByPhoneAsync(
            "call12345678",
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Contains(
            result.Errors,
            error => error.Code == IdentityErrorCodes.Validation);
        Assert.Null(store.NormalizedPhone);
    }

    [Fact]
    public async Task LookupByIdReturnsOnlyNonDeletedUsersAndFailsClosedWithoutStore()
    {
        var user = CreateUser();
        var lookup = new FakeLookupStore(null);
        var normalizer = new DefaultIdentityNormalizer();
        var metrics = new NoopIdentityMetrics();
        var absent = new IdentityUserLookupService<TestProfile>(lookup, normalizer, metrics);
        Assert.False((await absent.FindActiveByIdAsync(user.Id, CancellationToken.None)).IsSuccess);
        var active = new IdentityUserLookupService<TestProfile>(lookup, normalizer, metrics, new FakeUserStore(user));
        Assert.Equal(user, (await active.FindActiveByIdAsync(user.Id, CancellationToken.None)).Value);
        var deleted = new IdentityUserLookupService<TestProfile>(lookup, normalizer, metrics,
            new FakeUserStore(user with { DeletedAt = DateTimeOffset.UtcNow }));
        var result = await deleted.FindActiveByIdAsync(user.Id, CancellationToken.None);
        Assert.False(result.IsSuccess);
        Assert.Contains(result.Errors, error => error.Code == IdentityErrorCodes.UserNotFound);
    }

    private sealed class FakeUserStore(IdentityUser<TestProfile>? user) : IIdentityUserStore<TestProfile>
    {
        public Task<IdentityUser<TestProfile>?> FindByIdAsync(Guid id, CancellationToken ct)
            => Task.FromResult(user?.Id == id ? user : null);
        public Task<OperationResult<IdentityUser<TestProfile>>> CreateAsync(NewIdentityUser<TestProfile> user, Skopka.Identity.Users.Handles.NormalizedHandles handles, DateTimeOffset now, CancellationToken ct) => throw new NotSupportedException();
        public Task<OperationResult<IdentityUser<TestProfile>>> UpdateHandlesAsync(Guid id, long version, Skopka.Identity.Users.Handles.UpdatedHandles handles, DateTimeOffset now, CancellationToken ct) => throw new NotSupportedException();
        public Task<OperationResult<IdentityUser<TestProfile>>> UpdateProfileAsync(Guid id, long version, TestProfile profile, DateTimeOffset now, CancellationToken ct) => throw new NotSupportedException();
        public Task<OperationResult<IdentityUser<TestProfile>>> UpdateSecurityStampAsync(Guid id, long version, string stamp, DateTimeOffset now, CancellationToken ct) => throw new NotSupportedException();
        public Task<OperationResult> UpdateStateAsync(Guid id, long version, DateTimeOffset? deleted, DateTimeOffset? blocked, DateTimeOffset? until, string? stamp, DateTimeOffset now, CancellationToken ct) => throw new NotSupportedException();
    }

    private static IdentityUser<TestProfile> CreateUser()
        => new(
            Guid.NewGuid(),
            UserFlags.None,
            "alice",
            "alice@example.com",
            false,
            null,
            false,
            new TestProfile("Alice"),
            1,
            "SECURITY-STAMP",
            null,
            null,
            null,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow);

    private sealed class FakeLookupStore(
        IdentityUser<TestProfile>? user)
        : IIdentityUserLookupStore<TestProfile>
    {
        public string? NormalizedEmail { get; private set; }
        public string? NormalizedPhone { get; private set; }

        public Task<IdentityUser<TestProfile>?>
            FindActiveByNormalizedUserNameAsync(
                string normalizedUserName,
                CancellationToken ct)
            => Task.FromResult<IdentityUser<TestProfile>?>(null);

        public Task<IdentityUser<TestProfile>?>
            FindActiveByNormalizedEmailAsync(
                string normalizedEmail,
                CancellationToken ct)
        {
            NormalizedEmail = normalizedEmail;
            return Task.FromResult(user);
        }

        public Task<IdentityUser<TestProfile>?>
            FindActiveByNormalizedPhoneAsync(
                string normalizedPhone,
                CancellationToken ct)
        {
            NormalizedPhone = normalizedPhone;
            return Task.FromResult(user);
        }
    }

    private sealed record TestProfile(string DisplayName);
}
