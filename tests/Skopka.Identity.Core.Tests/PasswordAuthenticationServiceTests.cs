using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Authentication;
using Skopka.Identity.Credentials;
using Skopka.Identity.Errors;
using Skopka.Identity.Metrics;
using Skopka.Identity.Users;
using Xunit;

namespace Skopka.Identity.Core.Tests;

public sealed class PasswordAuthenticationServiceTests
{
    [Fact]
    public async Task AuthenticatesByNormalizedUserName()
    {
        var fixture = new Fixture();

        var result = await fixture.Service.AuthenticateAsync(
            new AuthenticatePasswordCommand(
                PasswordLoginHandle.UserName,
                " Alice ",
                "correct"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal(fixture.User, result.Value);
        Assert.Equal("ALICE", fixture.LookupStore.LastNormalizedUserName);
        Assert.Null(fixture.LookupStore.LastNormalizedEmail);
    }

    [Fact]
    public async Task AuthenticatesByNormalizedEmail()
    {
        var fixture = new Fixture();

        var result = await fixture.Service.AuthenticateAsync(
            new AuthenticatePasswordCommand(
                PasswordLoginHandle.Email,
                " Alice@Example.com ",
                "correct"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal("ALICE@EXAMPLE.COM", fixture.LookupStore.LastNormalizedEmail);
        Assert.Null(fixture.LookupStore.LastNormalizedUserName);
    }

    [Fact]
    public async Task UnknownUserAndWrongPasswordReturnSameError()
    {
        var unknown = new Fixture(userExists: false);
        var wrongPassword = new Fixture();

        var unknownResult = await unknown.Service.AuthenticateAsync(
            new AuthenticatePasswordCommand(
                PasswordLoginHandle.UserName,
                "unknown",
                "wrong"),
            CancellationToken.None);
        var wrongResult = await wrongPassword.Service.AuthenticateAsync(
            new AuthenticatePasswordCommand(
                PasswordLoginHandle.UserName,
                "alice",
                "wrong"),
            CancellationToken.None);

        AssertError(unknownResult, IdentityErrorCodes.InvalidCredentials);
        AssertError(wrongResult, IdentityErrorCodes.InvalidCredentials);
        Assert.Equal(1, unknown.TimingProtector.SimulateCalls);
        Assert.Contains(Guid.Empty, unknown.CredentialStore.FindUserIds);
        Assert.Equal(0, wrongPassword.TimingProtector.SimulateCalls);
    }

    [Fact]
    public async Task MissingCredentialUsesDummyVerification()
    {
        var fixture = new Fixture(passwordVerifier: null);

        var result = await fixture.Service.AuthenticateAsync(
            new AuthenticatePasswordCommand(
                PasswordLoginHandle.UserName,
                "alice",
                "wrong"),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.InvalidCredentials);
        Assert.Equal(1, fixture.TimingProtector.SimulateCalls);
    }

    [Fact]
    public async Task ValidPasswordReportsActiveBlock()
    {
        var fixture = new Fixture(
            blockedAt: DateTimeOffset.UtcNow.AddMinutes(-1),
            blockedUntil: DateTimeOffset.UtcNow.AddMinutes(10));

        var result = await fixture.Service.AuthenticateAsync(
            new AuthenticatePasswordCommand(
                PasswordLoginHandle.UserName,
                "alice",
                "correct"),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.AuthenticationBlocked);
    }

    [Fact]
    public async Task ExpiredTemporaryBlockAllowsAuthentication()
    {
        var fixture = new Fixture(
            blockedAt: DateTimeOffset.UtcNow.AddMinutes(-10),
            blockedUntil: DateTimeOffset.UtcNow.AddMinutes(-1));

        var result = await fixture.Service.AuthenticateAsync(
            new AuthenticatePasswordCommand(
                PasswordLoginHandle.UserName,
                "alice",
                "correct"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task SuccessfulAuthenticationRehashesOutdatedVerifier()
    {
        var fixture = new Fixture(passwordVerifier: "legacy");
        fixture.Hasher.LegacyVerifierNeedsRehash = true;
        fixture.LookupStore.UserAfterFirstLookup = fixture.User with
        {
            Version = fixture.User.Version + 1
        };

        var result = await fixture.Service.AuthenticateAsync(
            new AuthenticatePasswordCommand(
                PasswordLoginHandle.UserName,
                "alice",
                "correct"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal("legacy", fixture.CredentialStore.LastExpectedPasswordVerifier);
        Assert.Equal("hash:correct", fixture.CredentialStore.PasswordVerifier);
        Assert.Equal(fixture.User.Version, fixture.CredentialStore.LastExpectedVersion);
        Assert.Equal(fixture.User.Version + 1, result.Value.Version);
    }

    [Fact]
    public async Task RehashConcurrencyDoesNotRejectValidAuthentication()
    {
        var fixture = new Fixture(passwordVerifier: "legacy");
        fixture.Hasher.LegacyVerifierNeedsRehash = true;
        fixture.CredentialStore.ReplaceResult = OperationResultFactory.Fail(
            new Error(
                IdentityErrorCodes.ConcurrencyConflict,
                "Concurrency conflict.",
                ErrorType.Conflict));

        var result = await fixture.Service.AuthenticateAsync(
            new AuthenticatePasswordCommand(
                PasswordLoginHandle.UserName,
                "alice",
                "correct"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void TimingProtectorCreatesOneDummyVerifierAndReusesIt()
    {
        var hasher = new FakePasswordHasher();
        var protector = new PasswordVerificationTimingProtector(hasher);

        protector.SimulateVerification("first");
        protector.SimulateVerification("second");

        Assert.Equal(1, hasher.HashCalls);
        Assert.Equal(2, hasher.VerifyCalls);
    }

    private static void AssertError(
        OperationResult<IdentityUser<TestProfile>> result,
        string errorCode)
    {
        Assert.False(result.IsSuccess);
        Assert.Contains(result.Errors, error => error.Code == errorCode);
    }

    private sealed class Fixture
    {
        public Fixture(
            bool userExists = true,
            string? passwordVerifier = "hash:correct",
            DateTimeOffset? blockedAt = null,
            DateTimeOffset? blockedUntil = null)
        {
            User = new IdentityUser<TestProfile>(
                Guid.NewGuid(),
                UserFlags.None,
                "alice",
                "alice@example.com",
                true,
                null,
                false,
                new TestProfile("Alice"),
                3,
                null,
                blockedAt,
                blockedUntil,
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddDays(-1));

            LookupStore = new FakeUserLookupStore(userExists ? User : null);
            CredentialStore = new FakePasswordCredentialStore(passwordVerifier);
            Hasher = new FakePasswordHasher();
            TimingProtector = new FakeTimingProtector();
            Service = new PasswordAuthenticationService<TestProfile>(
                LookupStore,
                CredentialStore,
                new DefaultIdentityNormalizer(),
                Hasher,
                TimingProtector,
                new NoopIdentityMetrics());
        }

        public IdentityUser<TestProfile> User { get; }
        public FakeUserLookupStore LookupStore { get; }
        public FakePasswordCredentialStore CredentialStore { get; }
        public FakePasswordHasher Hasher { get; }
        public FakeTimingProtector TimingProtector { get; }
        public PasswordAuthenticationService<TestProfile> Service { get; }
    }

    private sealed class FakeUserLookupStore(IdentityUser<TestProfile>? user)
        : IIdentityUserLookupStore<TestProfile>
    {
        public string? LastNormalizedUserName { get; private set; }
        public string? LastNormalizedEmail { get; private set; }
        public IdentityUser<TestProfile>? UserAfterFirstLookup { get; set; }
        private int lookupCalls;

        public Task<IdentityUser<TestProfile>?> FindActiveByNormalizedUserNameAsync(
            string normalizedUserName,
            CancellationToken ct)
        {
            LastNormalizedUserName = normalizedUserName;
            return Task.FromResult(GetUser());
        }

        public Task<IdentityUser<TestProfile>?> FindActiveByNormalizedEmailAsync(
            string normalizedEmail,
            CancellationToken ct)
        {
            LastNormalizedEmail = normalizedEmail;
            return Task.FromResult(GetUser());
        }

        private IdentityUser<TestProfile>? GetUser()
        {
            lookupCalls++;
            return lookupCalls > 1 && UserAfterFirstLookup is not null
                ? UserAfterFirstLookup
                : user;
        }
    }

    private sealed class FakePasswordCredentialStore(string? passwordVerifier)
        : IPasswordCredentialStore<TestProfile>
    {
        public string? PasswordVerifier { get; private set; } = passwordVerifier;
        public string? LastExpectedPasswordVerifier { get; private set; }
        public long LastExpectedVersion { get; private set; }
        public List<Guid> FindUserIds { get; } = [];
        public OperationResult ReplaceResult { get; set; } =
            OperationResultFactory.Success();

        public Task<string?> FindPasswordVerifierAsync(
            Guid userId,
            CancellationToken ct)
        {
            FindUserIds.Add(userId);
            return Task.FromResult(PasswordVerifier);
        }

        public Task<OperationResult> ReplacePasswordVerifierAsync(
            Guid userId,
            long expectedVersion,
            string? expectedPasswordVerifier,
            string? newPasswordVerifier,
            DateTimeOffset now,
            CancellationToken ct)
        {
            LastExpectedVersion = expectedVersion;
            LastExpectedPasswordVerifier = expectedPasswordVerifier;

            if (ReplaceResult.IsSuccess)
            {
                PasswordVerifier = newPasswordVerifier;
            }

            return Task.FromResult(ReplaceResult);
        }
    }

    private sealed class FakePasswordHasher : IPasswordHasher
    {
        public bool LegacyVerifierNeedsRehash { get; set; }
        public int HashCalls { get; private set; }
        public int VerifyCalls { get; private set; }

        public string HashPassword(string password)
        {
            HashCalls++;
            return $"hash:{password}";
        }

        public PasswordVerificationResult VerifyHashedPassword(
            string passwordVerifier,
            string providedPassword)
        {
            VerifyCalls++;

            if (passwordVerifier == "legacy"
                && providedPassword == "correct"
                && LegacyVerifierNeedsRehash)
            {
                return PasswordVerificationResult.SuccessRehashNeeded;
            }

            return passwordVerifier == $"hash:{providedPassword}"
                ? PasswordVerificationResult.Success
                : PasswordVerificationResult.Failed;
        }
    }

    private sealed class FakeTimingProtector
        : IPasswordVerificationTimingProtector
    {
        public int SimulateCalls { get; private set; }

        public void SimulateVerification(string providedPassword)
            => SimulateCalls++;
    }

    public sealed record TestProfile(string DisplayName);
}
