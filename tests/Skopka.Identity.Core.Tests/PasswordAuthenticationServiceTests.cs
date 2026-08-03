using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Authentication;
using Skopka.Identity.Credentials;
using Skopka.Identity.Errors;
using Skopka.Identity.Metrics;
using Skopka.Identity.RateLimiting;
using Skopka.Identity.Users;
using Xunit;

namespace Skopka.Identity.Core.Tests;

public sealed class PasswordAuthenticationServiceTests
{
    [Fact]
    public void LoginHandleValuesPreserveCompatibility()
    {
        Assert.Equal(0, (int)PasswordLoginHandle.UserName);
        Assert.Equal(1, (int)PasswordLoginHandle.Email);
        Assert.Equal(2, (int)PasswordLoginHandle.Phone);
        Assert.Equal(3, (int)PasswordLoginHandle.Automatic);
    }

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
    public async Task AuthenticatesByNormalizedPhone()
    {
        var fixture = new Fixture();

        var result = await fixture.Service.AuthenticateAsync(
            new AuthenticatePasswordCommand(
                PasswordLoginHandle.Phone,
                "+1 (234) 567-8901",
                "correct"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal("12345678901", fixture.LookupStore.LastNormalizedPhone);
        Assert.Null(fixture.LookupStore.LastNormalizedUserName);
        Assert.Null(fixture.LookupStore.LastNormalizedEmail);
    }

    [Fact]
    public async Task ExplicitPhoneRejectsNonPhoneShapedInputBeforeLookup()
    {
        var limiter = new FakeIdentityRateLimiter();
        var fixture = new Fixture(rateLimiter: limiter);

        var result = await fixture.Service.AuthenticateAsync(
            new AuthenticatePasswordCommand(
                PasswordLoginHandle.Phone,
                "call12345678",
                "correct"),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.Validation);
        Assert.Null(fixture.LookupStore.LastNormalizedPhone);
        Assert.Empty(limiter.Checks);
        Assert.Empty(limiter.Hits);
    }

    [Fact]
    public async Task AutomaticLoginResolvesWithOneStoreCall()
    {
        var fixture = new Fixture();

        var result = await fixture.Service.AuthenticateAsync(
            new AuthenticatePasswordCommand(
                PasswordLoginHandle.Automatic,
                " Alice@Example.com ",
                "correct"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal(1, fixture.LookupStore.AutomaticLookupCalls);
        Assert.Equal(
            ["ALICE@EXAMPLE.COM"],
            fixture.LookupStore.LastAutomaticKeys);
        Assert.Null(fixture.LookupStore.LastNormalizedUserName);
        Assert.Null(fixture.LookupStore.LastNormalizedEmail);
        Assert.Null(fixture.LookupStore.LastNormalizedPhone);
    }

    [Fact]
    public async Task AutomaticLoginWithoutMatchUsesOneDummyVerification()
    {
        var fixture = new Fixture(userExists: false);

        var result = await fixture.Service.AuthenticateAsync(
            new AuthenticatePasswordCommand(
                PasswordLoginHandle.Automatic,
                "unknown@example.com",
                "wrong"),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.InvalidCredentials);
        Assert.Equal(1, fixture.LookupStore.AutomaticLookupCalls);
        Assert.Equal(1, fixture.TimingProtector.SimulateCalls);
        Assert.Equal([Guid.Empty], fixture.CredentialStore.FindUserIds);
    }

    [Fact]
    public async Task AmbiguousAutomaticLoginUsesOneDummyVerification()
    {
        var fixture = new Fixture();
        fixture.LookupStore.AutomaticUsers =
        [
            fixture.User,
            fixture.User with { Id = Guid.NewGuid() },
        ];

        var result = await fixture.Service.AuthenticateAsync(
            new AuthenticatePasswordCommand(
                PasswordLoginHandle.Automatic,
                "shared",
                "correct"),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.InvalidCredentials);
        Assert.Equal(1, fixture.LookupStore.AutomaticLookupCalls);
        Assert.Equal(1, fixture.TimingProtector.SimulateCalls);
        Assert.Equal([Guid.Empty], fixture.CredentialStore.FindUserIds);
        Assert.Equal(0, fixture.Hasher.VerifyCalls);
    }

    [Fact]
    public async Task AutomaticPhoneCandidatesIncludeDigitsOnlyAlias()
    {
        var fixture = new Fixture();

        var result = await fixture.Service.AuthenticateAsync(
            new AuthenticatePasswordCommand(
                PasswordLoginHandle.Automatic,
                "+1 (234) 567-8901",
                "correct"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Contains(
            "12345678901",
            fixture.LookupStore.LastAutomaticKeys!);
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
    public async Task RehashRejectsHandleReassignedToAnotherUser()
    {
        var fixture = new Fixture(passwordVerifier: "legacy");
        fixture.Hasher.LegacyVerifierNeedsRehash = true;
        fixture.LookupStore.UserAfterFirstLookup = fixture.User with
        {
            Id = Guid.NewGuid(),
            Version = fixture.User.Version + 1
        };

        var result = await fixture.Service.AuthenticateAsync(
            new AuthenticatePasswordCommand(
                PasswordLoginHandle.UserName,
                "alice",
                "correct"),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.InvalidCredentials);
    }

    [Fact]
    public async Task AutomaticRehashReusesOriginalCustomAliasLookup()
    {
        var fixture = new Fixture(
            passwordVerifier: "legacy",
            normalizer: new AliasOnlyNormalizer());
        fixture.Hasher.LegacyVerifierNeedsRehash = true;
        fixture.LookupStore.AutomaticUsersAfterFirstLookup =
        [
            fixture.User with { Version = fixture.User.Version + 1 }
        ];

        var result = await fixture.Service.AuthenticateAsync(
            new AuthenticatePasswordCommand(
                PasswordLoginHandle.Automatic,
                "custom-alias",
                "correct"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal(fixture.User.Version + 1, result.Value.Version);
        Assert.Equal(2, fixture.LookupStore.AutomaticLookupCalls);
    }

    [Fact]
    public async Task WrongPasswordHitsClientAndAccountPartitions()
    {
        var limiter = new FakeIdentityRateLimiter();
        var fixture = new Fixture(rateLimiter: limiter);

        var result = await fixture.Service.AuthenticateAsync(
            new AuthenticatePasswordCommand(
                PasswordLoginHandle.UserName,
                "alice",
                "wrong",
                "ip:203.0.113.10"),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.InvalidCredentials);
        Assert.Contains(
            limiter.Hits,
            request => request.Scope == "password.client");
        Assert.Contains(
            limiter.Hits,
            request => request.Scope == "password.account");
        Assert.Empty(limiter.Resets);
    }

    [Fact]
    public async Task ResolvedUserSharesAccountBucketAcrossHandlesAndFormats()
    {
        var limiter = new FakeIdentityRateLimiter();
        var fixture = new Fixture(rateLimiter: limiter);

        var first = await fixture.Service.AuthenticateAsync(
            new AuthenticatePasswordCommand(
                PasswordLoginHandle.Automatic,
                "+1 (234) 567-8901",
                "wrong"),
            CancellationToken.None);
        var second = await fixture.Service.AuthenticateAsync(
            new AuthenticatePasswordCommand(
                PasswordLoginHandle.Automatic,
                "123.456.789.01",
                "wrong"),
            CancellationToken.None);
        var third = await fixture.Service.AuthenticateAsync(
            new AuthenticatePasswordCommand(
                PasswordLoginHandle.Email,
                "alice@example.com",
                "wrong"),
            CancellationToken.None);

        AssertError(first, IdentityErrorCodes.InvalidCredentials);
        AssertError(second, IdentityErrorCodes.InvalidCredentials);
        AssertError(third, IdentityErrorCodes.InvalidCredentials);

        var accountChecks = limiter.Checks
            .Where(request => request.Scope
                == "password.account")
            .ToArray();
        var accountHits = limiter.Hits
            .Where(request => request.Scope
                == "password.account")
            .ToArray();
        Assert.Equal(3, accountChecks.Length);
        Assert.Equal(3, accountHits.Length);
        Assert.Single(accountChecks.Select(request => request.Key).Distinct());
        Assert.Single(accountHits.Select(request => request.Key).Distinct());
        Assert.Equal($"user:{fixture.User.Id:N}", accountChecks[0].Key);
        Assert.Equal(accountChecks[0].Key, accountHits[0].Key);
    }

    [Fact]
    public async Task UnknownPhoneFormatsShareDeterministicFallbackBucket()
    {
        var limiter = new FakeIdentityRateLimiter();
        var fixture = new Fixture(userExists: false, rateLimiter: limiter);

        _ = await fixture.Service.AuthenticateAsync(
            new AuthenticatePasswordCommand(
                PasswordLoginHandle.Automatic,
                "+1 (234) 567-8901",
                "wrong"),
            CancellationToken.None);
        _ = await fixture.Service.AuthenticateAsync(
            new AuthenticatePasswordCommand(
                PasswordLoginHandle.Automatic,
                "123.456.789.01",
                "wrong"),
            CancellationToken.None);

        var accountKeys = limiter.Checks
            .Where(request => request.Scope
                == "password.account")
            .Select(request => request.Key)
            .ToArray();
        Assert.Equal(2, accountKeys.Length);
        Assert.Single(accountKeys.Distinct());
    }

    [Fact]
    public async Task SuccessfulPasswordResetsOnlyAccountPartition()
    {
        var limiter = new FakeIdentityRateLimiter();
        var fixture = new Fixture(rateLimiter: limiter);

        var result = await fixture.Service.AuthenticateAsync(
            new AuthenticatePasswordCommand(
                PasswordLoginHandle.UserName,
                "alice",
                "correct",
                "ip:203.0.113.10"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Single(
            limiter.Resets,
            reset => reset.Scope == "password.account");
        Assert.DoesNotContain(
            limiter.Resets,
            reset => reset.Scope == "password.client");
    }

    [Fact]
    public async Task AccountRateLimitRunsDummyVerification()
    {
        var limiter = new FakeIdentityRateLimiter
        {
            CheckDecision = new RateLimitDecision(
                false,
                DateTimeOffset.UtcNow.AddMinutes(1)),
        };
        var fixture = new Fixture(rateLimiter: limiter);

        var result = await fixture.Service.AuthenticateAsync(
            new AuthenticatePasswordCommand(
                PasswordLoginHandle.UserName,
                "alice",
                "correct"),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.RateLimitExceeded);
        Assert.Equal(1, fixture.TimingProtector.SimulateCalls);
        Assert.Equal(0, fixture.Hasher.VerifyCalls);
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

    [Fact]
    public async Task OversizedPasswordIsRejectedBeforeLookupOrKdf()
    {
        var fixture = new Fixture(
            passwordPolicyOptions: new PasswordPolicyOptions
            {
                MinimumLength = 8,
                MaximumLength = 64
            });

        var result = await fixture.Service.AuthenticateAsync(
            new AuthenticatePasswordCommand(
                PasswordLoginHandle.UserName,
                "alice",
                new string('x', 65)),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.Validation);
        Assert.Null(fixture.LookupStore.LastNormalizedUserName);
        Assert.Empty(fixture.CredentialStore.FindUserIds);
        Assert.Equal(0, fixture.Hasher.VerifyCalls);
        Assert.Equal(0, fixture.TimingProtector.SimulateCalls);
    }

    [Fact]
    public async Task OversizedLoginIsRejectedBeforeRateLimiterOrLookup()
    {
        var limiter = new FakeIdentityRateLimiter();
        var fixture = new Fixture(rateLimiter: limiter);

        var result = await fixture.Service.AuthenticateAsync(
            new AuthenticatePasswordCommand(
                PasswordLoginHandle.Automatic,
                new string('x', IdentityLoginLimits.MaximumLoginLength + 1),
                "correct",
                "client"),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.Validation);
        Assert.Empty(limiter.Checks);
        Assert.Empty(limiter.Hits);
        Assert.Equal(0, fixture.LookupStore.AutomaticLookupCalls);
        Assert.Empty(fixture.CredentialStore.FindUserIds);
        Assert.Equal(0, fixture.Hasher.VerifyCalls);
        Assert.Equal(0, fixture.TimingProtector.SimulateCalls);
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
            DateTimeOffset? blockedUntil = null,
            FakeIdentityRateLimiter? rateLimiter = null,
            PasswordPolicyOptions? passwordPolicyOptions = null,
            IIdentityNormalizer? normalizer = null)
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
                "SECURITY-STAMP",
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
                normalizer ?? new DefaultIdentityNormalizer(),
                Hasher,
                TimingProtector,
                new NoopIdentityMetrics(),
                passwordPolicyOptions ?? new PasswordPolicyOptions
                {
                    MinimumLength = 8,
                    MaximumLength = 128
                },
                new IdentityRateLimitOptions(),
                rateLimiter is null ? [] : [rateLimiter]);
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
        public string? LastNormalizedPhone { get; private set; }
        public IReadOnlyCollection<string>? LastAutomaticKeys { get; private set; }
        public int AutomaticLookupCalls { get; private set; }
        public IReadOnlyList<IdentityUser<TestProfile>> AutomaticUsers { get; set; }
            = user is null ? [] : [user];
        public IReadOnlyList<IdentityUser<TestProfile>>?
            AutomaticUsersAfterFirstLookup { get; set; }
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

        public Task<IdentityUser<TestProfile>?> FindActiveByNormalizedPhoneAsync(
            string normalizedPhone,
            CancellationToken ct)
        {
            LastNormalizedPhone = normalizedPhone;
            return Task.FromResult(GetUser());
        }

        public Task<IReadOnlyList<IdentityUser<TestProfile>>>
            FindActiveByNormalizedLoginIdentifiersAsync(
                IReadOnlyCollection<string> normalizedKeys,
                CancellationToken ct)
        {
            AutomaticLookupCalls++;
            LastAutomaticKeys = normalizedKeys;
            lookupCalls++;
            return Task.FromResult(
                lookupCalls > 1
                    && AutomaticUsersAfterFirstLookup is not null
                        ? AutomaticUsersAfterFirstLookup
                        : AutomaticUsers);
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
            string? newSecurityStamp,
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

    private sealed class AliasOnlyNormalizer : IIdentityNormalizer
    {
        public string? NormalizeUserName(string? value) => null;
        public string? NormalizeEmail(string? value) => null;
        public string? NormalizePhone(string? value) => null;

        public IReadOnlyCollection<string> NormalizeAutomaticLoginIdentifiers(
            string? value)
            => value is null ? [] : ["CUSTOM-ALIAS"];
    }

    private sealed class FakeIdentityRateLimiter
        : IIdentityRateLimiter<TestProfile>
    {
        public RateLimitDecision CheckDecision { get; set; } =
            new(true, null);
        public RateLimitDecision HitDecision { get; set; } =
            new(true, null);
        public List<RateLimitRequest> Checks { get; } = [];
        public List<RateLimitRequest> Hits { get; } = [];
        public List<(string Scope, string Key)> Resets { get; } = [];

        public Task<RateLimitDecision> CheckAsync(
            RateLimitRequest request,
            CancellationToken ct)
        {
            Checks.Add(request);
            return Task.FromResult(CheckDecision);
        }

        public Task<RateLimitDecision> HitAsync(
            RateLimitRequest request,
            CancellationToken ct)
        {
            Hits.Add(request);
            return Task.FromResult(HitDecision);
        }

        public Task ResetAsync(
            string scope,
            string key,
            CancellationToken ct)
        {
            Resets.Add((scope, key));
            return Task.CompletedTask;
        }

        public Task<int> PruneAsync(CancellationToken ct)
            => Task.FromResult(0);
    }

    public sealed record TestProfile(string DisplayName);
}
