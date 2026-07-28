using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;
using Skopka.Identity.Metrics;
using Skopka.Identity.RateLimiting;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Handles;
using Skopka.Identity.Verification;
using Xunit;

namespace Skopka.Identity.Core.Tests;

public sealed class IdentityVerificationServiceTests
{
    [Fact]
    public async Task BeginBindsChallengeToUserPurposeIntentAndStamp()
    {
        var fixture = new Fixture();

        var result = await fixture.Service.BeginAsync(
            new BeginVerificationCommand(
                fixture.UserStore.User.Id,
                "orders.cancel",
                "order-42:v3",
                VerificationMethods.OneTimeCode),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal("123456", result.Value.DeliveryCode);
        Assert.NotNull(fixture.ChallengeStore.Challenge);
        Assert.Equal(
            fixture.UserStore.User.Id,
            fixture.ChallengeStore.Challenge.UserId);
        Assert.Equal("orders.cancel", fixture.ChallengeStore.Challenge.Purpose);
        Assert.Equal("order-42:v3", fixture.ChallengeStore.Challenge.Binding);
        Assert.Equal(
            fixture.UserStore.User.SecurityStamp,
            fixture.ChallengeStore.Challenge.SecurityStamp);
    }

    [Fact]
    public async Task InvalidResponsesLockChallengeAtAttemptLimit()
    {
        var fixture = new Fixture(maxAttempts: 2);
        var challenge = await fixture.BeginAsync();

        var first = await fixture.Service.VerifyAsync(
            new VerifyVerificationChallengeCommand(
                challenge.ChallengeId,
                fixture.UserStore.User.Id,
                "000000"),
            CancellationToken.None);
        var second = await fixture.Service.VerifyAsync(
            new VerifyVerificationChallengeCommand(
                challenge.ChallengeId,
                fixture.UserStore.User.Id,
                "000000"),
            CancellationToken.None);

        AssertError(first, IdentityErrorCodes.VerificationResponseInvalid);
        AssertError(second, IdentityErrorCodes.VerificationAttemptsExceeded);
        Assert.Equal(
            VerificationChallengeState.Locked,
            fixture.ChallengeStore.Challenge!.State);
        Assert.Equal(2, fixture.ChallengeStore.Challenge.FailedAttemptCount);
    }

    [Fact]
    public async Task ProofIsBoundToIntentAndCanBeConsumedOnlyOnce()
    {
        var fixture = new Fixture();
        var challenge = await fixture.BeginAsync();
        var verification = await fixture.Service.VerifyAsync(
            new VerifyVerificationChallengeCommand(
                challenge.ChallengeId,
                fixture.UserStore.User.Id,
                "123456"),
            CancellationToken.None);
        Assert.True(verification.IsSuccess);

        var wrongBinding = await fixture.Service.ConsumeAsync(
            new ConsumeVerificationProofCommand(
                challenge.ChallengeId,
                fixture.UserStore.User.Id,
                "profile.delete",
                "different-intent",
                verification.Value.Token),
            CancellationToken.None);
        var first = await fixture.Service.ConsumeAsync(
            new ConsumeVerificationProofCommand(
                challenge.ChallengeId,
                fixture.UserStore.User.Id,
                "profile.delete",
                "profile-7:v1",
                verification.Value.Token),
            CancellationToken.None);
        var replay = await fixture.Service.ConsumeAsync(
            new ConsumeVerificationProofCommand(
                challenge.ChallengeId,
                fixture.UserStore.User.Id,
                "profile.delete",
                "profile-7:v1",
                verification.Value.Token),
            CancellationToken.None);

        AssertError(wrongBinding, IdentityErrorCodes.VerificationProofInvalid);
        Assert.True(first.IsSuccess);
        AssertError(replay, IdentityErrorCodes.VerificationProofInvalid);
        Assert.Equal(
            VerificationChallengeState.Consumed,
            fixture.ChallengeStore.Challenge!.State);
    }

    [Fact]
    public async Task SecurityStampChangeInvalidatesVerifiedProof()
    {
        var fixture = new Fixture();
        var challenge = await fixture.BeginAsync();
        var verification = await fixture.Service.VerifyAsync(
            new VerifyVerificationChallengeCommand(
                challenge.ChallengeId,
                fixture.UserStore.User.Id,
                "123456"),
            CancellationToken.None);
        Assert.True(verification.IsSuccess);

        fixture.UserStore.User = fixture.UserStore.User with
        {
            SecurityStamp = "ROTATED-STAMP",
        };
        var result = await fixture.Service.ConsumeAsync(
            new ConsumeVerificationProofCommand(
                challenge.ChallengeId,
                fixture.UserStore.User.Id,
                "profile.delete",
                "profile-7:v1",
                verification.Value.Token),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.VerificationProofInvalid);
        Assert.Equal(
            VerificationChallengeState.Verified,
            fixture.ChallengeStore.Challenge!.State);
    }

    [Fact]
    public async Task ExpiredProofCannotBeConsumed()
    {
        var fixture = new Fixture();
        var challenge = await fixture.BeginAsync();
        var verification = await fixture.Service.VerifyAsync(
            new VerifyVerificationChallengeCommand(
                challenge.ChallengeId,
                fixture.UserStore.User.Id,
                "123456"),
            CancellationToken.None);
        Assert.True(verification.IsSuccess);
        fixture.ChallengeStore.ExpireProof();

        var result = await fixture.Service.ConsumeAsync(
            new ConsumeVerificationProofCommand(
                challenge.ChallengeId,
                fixture.UserStore.User.Id,
                "profile.delete",
                "profile-7:v1",
                verification.Value.Token),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.VerificationProofInvalid);
    }

    [Fact]
    public async Task BeginUsesClientAccountAndIntentPartitions()
    {
        var limiter = new FakeIdentityRateLimiter();
        var fixture = new Fixture(rateLimiter: limiter);

        var result = await fixture.Service.BeginAsync(
            new BeginVerificationCommand(
                fixture.UserStore.User.Id,
                "profile.delete",
                "profile-7:v1",
                VerificationMethods.OneTimeCode,
                "ip:203.0.113.10"),
            CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Contains(
            limiter.Hits,
            request => request.Scope == "verification.client");
        Assert.Contains(
            limiter.Hits,
            request => request.Scope == "verification.account");
        Assert.Contains(
            limiter.Hits,
            request => request.Scope == "verification.intent"
                && request.MinimumInterval == TimeSpan.FromSeconds(30));
    }

    [Fact]
    public async Task ResendCooldownPreventsIssuingSecondCode()
    {
        var intentHits = 0;
        var limiter = new FakeIdentityRateLimiter
        {
            HitHandler = request =>
            {
                if (request.Scope != "verification.intent")
                {
                    return new RateLimitDecision(true, null);
                }

                intentHits++;
                return intentHits == 1
                    ? new RateLimitDecision(true, null)
                    : new RateLimitDecision(
                        false,
                        DateTimeOffset.UtcNow.AddSeconds(30));
            },
        };
        var fixture = new Fixture(rateLimiter: limiter);

        var first = await fixture.BeginAsync();
        var second = await fixture.Service.BeginAsync(
            new BeginVerificationCommand(
                fixture.UserStore.User.Id,
                "profile.delete",
                "profile-7:v1",
                VerificationMethods.OneTimeCode),
            CancellationToken.None);

        Assert.NotNull(first);
        AssertError(second, IdentityErrorCodes.RateLimitExceeded);
        Assert.Equal(1, fixture.MethodProvider.IssueCalls);
    }

    private static void AssertError(OperationResult result, string code)
    {
        Assert.False(result.IsSuccess);
        Assert.Contains(result.Errors, error => error.Code == code);
    }

    private sealed class Fixture
    {
        public Fixture(
            int maxAttempts = 5,
            FakeIdentityRateLimiter? rateLimiter = null)
        {
            UserStore = new FakeIdentityUserStore(CreateUser());
            ChallengeStore = new FakeVerificationChallengeStore();
            MethodProvider = new FakeVerificationMethodProvider();
            Service = new IdentityVerificationService<TestProfile>(
                ChallengeStore,
                UserStore,
                [MethodProvider],
                new VerificationOptions
                {
                    ChallengeLifetime = TimeSpan.FromMinutes(5),
                    ProofLifetime = TimeSpan.FromMinutes(2),
                    MaxAttempts = maxAttempts,
                },
                new NoopIdentityMetrics(),
                new IdentityRateLimitOptions(),
                rateLimiter is null ? [] : [rateLimiter]);
        }

        public FakeIdentityUserStore UserStore { get; }
        public FakeVerificationChallengeStore ChallengeStore { get; }
        public FakeVerificationMethodProvider MethodProvider { get; }
        public IdentityVerificationService<TestProfile> Service { get; }

        public async Task<IssuedVerificationChallenge> BeginAsync()
        {
            var result = await Service.BeginAsync(
                new BeginVerificationCommand(
                    UserStore.User.Id,
                    "profile.delete",
                    "profile-7:v1",
                    VerificationMethods.OneTimeCode),
                CancellationToken.None);
            Assert.True(result.IsSuccess);
            return result.Value;
        }
    }

    private sealed class FakeVerificationMethodProvider
        : IVerificationMethodProvider
    {
        public string Method => VerificationMethods.OneTimeCode;
        public int IssueCalls { get; private set; }

        public Task<IssuedVerificationMethodChallenge> IssueAsync(
            VerificationMethodContext context,
            CancellationToken ct)
        {
            IssueCalls++;
            return Task.FromResult(
                new IssuedVerificationMethodChallenge(
                    "fixed-verifier",
                    "123456"));
        }

        public Task<bool> VerifyAsync(
            VerificationMethodContext context,
            string verifier,
            string response,
            CancellationToken ct)
            => Task.FromResult(
                verifier == "fixed-verifier"
                && response == "123456");
    }

    private sealed class FakeIdentityRateLimiter
        : IIdentityRateLimiter<TestProfile>
    {
        public Func<RateLimitRequest, RateLimitDecision>? HitHandler
        {
            get;
            init;
        }

        public List<RateLimitRequest> Hits { get; } = [];

        public Task<RateLimitDecision> CheckAsync(
            RateLimitRequest request,
            CancellationToken ct)
            => Task.FromResult(new RateLimitDecision(true, null));

        public Task<RateLimitDecision> HitAsync(
            RateLimitRequest request,
            CancellationToken ct)
        {
            Hits.Add(request);
            return Task.FromResult(
                HitHandler?.Invoke(request)
                ?? new RateLimitDecision(true, null));
        }

        public Task ResetAsync(
            string scope,
            string key,
            CancellationToken ct)
            => Task.CompletedTask;

        public Task<int> PruneAsync(CancellationToken ct)
            => Task.FromResult(0);
    }

    private sealed class FakeVerificationChallengeStore
        : IVerificationChallengeStore<TestProfile>
    {
        public StoredVerificationChallenge? Challenge { get; private set; }

        public void ExpireProof()
        {
            Assert.NotNull(Challenge);
            Challenge = Challenge with
            {
                ProofExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1),
            };
        }

        public Task<StoredVerificationChallenge?> FindByIdAsync(
            Guid challengeId,
            CancellationToken ct)
            => Task.FromResult(
                Challenge?.Id == challengeId ? Challenge : null);

        public Task<OperationResult> CreateAsync(
            NewVerificationChallenge challenge,
            DateTimeOffset now,
            CancellationToken ct)
        {
            Challenge = new StoredVerificationChallenge(
                challenge.Id,
                challenge.UserId,
                challenge.Purpose,
                challenge.Binding,
                challenge.Method,
                challenge.Verifier,
                challenge.SecurityStamp,
                0,
                challenge.MaxAttempts,
                VerificationChallengeState.Pending,
                null,
                null,
                1,
                challenge.ExpiresAt,
                now,
                now,
                null,
                null);
            return Task.FromResult(OperationResultFactory.Success());
        }

        public Task<OperationResult<StoredVerificationChallenge>>
            RecordAttemptAsync(
                Guid challengeId,
                long expectedVersion,
                bool succeeded,
                string? proofHash,
                DateTimeOffset? proofExpiresAt,
                DateTimeOffset now,
                CancellationToken ct)
        {
            Assert.NotNull(Challenge);
            var failedAttempts = Challenge.FailedAttemptCount
                + (succeeded ? 0 : 1);
            var state = succeeded
                ? VerificationChallengeState.Verified
                : failedAttempts >= Challenge.MaxAttempts
                    ? VerificationChallengeState.Locked
                    : VerificationChallengeState.Pending;
            Challenge = Challenge with
            {
                FailedAttemptCount = failedAttempts,
                State = state,
                ProofHash = proofHash,
                ProofExpiresAt = proofExpiresAt,
                Version = Challenge.Version + 1,
                ModifiedAt = now,
                VerifiedAt = succeeded ? now : null,
            };

            return Task.FromResult(
                OperationResultFactory.Success(Challenge));
        }

        public Task<OperationResult> ConsumeProofAsync(
            Guid challengeId,
            long expectedVersion,
            Guid userId,
            string purpose,
            string binding,
            string proofHash,
            string securityStamp,
            DateTimeOffset now,
            CancellationToken ct)
        {
            Assert.NotNull(Challenge);
            Challenge = Challenge with
            {
                State = VerificationChallengeState.Consumed,
                Version = Challenge.Version + 1,
                ModifiedAt = now,
                ConsumedAt = now,
            };
            return Task.FromResult(OperationResultFactory.Success());
        }
    }

    private sealed class FakeIdentityUserStore(IdentityUser<TestProfile> user)
        : IIdentityUserStore<TestProfile>
    {
        public IdentityUser<TestProfile> User { get; set; } = user;

        public Task<IdentityUser<TestProfile>?> FindByIdAsync(
            Guid id,
            CancellationToken ct)
            => Task.FromResult(id == User.Id ? User : null);

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

        public Task<OperationResult<IdentityUser<TestProfile>>>
            UpdateSecurityStampAsync(
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
            4,
            "CURRENT-STAMP",
            null,
            null,
            null,
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(-1));

    public sealed record TestProfile(string DisplayName);
}
