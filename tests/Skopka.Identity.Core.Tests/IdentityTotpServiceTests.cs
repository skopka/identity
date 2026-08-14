using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Metrics;
using Skopka.Identity.RateLimiting;
using Skopka.Identity.Totp;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Handles;
using Skopka.Identity.Verification;
using Xunit;

namespace Skopka.Identity.Core.Tests;

public sealed class IdentityTotpServiceTests
{
    [Fact]
    public async Task EnrollmentProtectsSecretAndBurnsConfirmationCode()
    {
        var user = CreateUser();
        var store = new FakeFactorStore();
        var codeProvider = new FakeCodeProvider();
        var service = new IdentityTotpService<TestProfile>(
            store,
            new FakeUserStore(user),
            codeProvider,
            new FakeSecretProtector(),
            new TotpOptions { RecoveryCodeCount = 4 },
            new IdentityRateLimitOptions(),
            [],
            new NoopIdentityMetrics());

        var begun = await service.BeginEnrollmentAsync(
            new BeginTotpEnrollmentCommand(user.Id, "client-a"),
            CancellationToken.None);

        Assert.True(begun.IsSuccess);
        Assert.Equal(FakeCodeProvider.Secret, begun.Value.Secret);
        Assert.NotNull(store.Factor);
        Assert.Equal(
            $"protected:{FakeCodeProvider.Secret}",
            store.Factor.ProtectedSecret);
        Assert.NotEqual(
            FakeCodeProvider.Secret,
            store.Factor.ProtectedSecret);

        var confirmed = await service.ConfirmEnrollmentAsync(
            new ConfirmTotpEnrollmentCommand(
                user.Id,
                begun.Value.EnrollmentId,
                FakeCodeProvider.Code,
                "client-a"),
            CancellationToken.None);

        Assert.True(confirmed.IsSuccess);
        Assert.True(confirmed.Value.Status.IsEnabled);
        Assert.Equal(4, confirmed.Value.RecoveryCodes.Count);
        Assert.Equal(4, confirmed.Value.RecoveryCodes.Distinct().Count());
        Assert.All(
            confirmed.Value.RecoveryCodes,
            code => Assert.Matches(
                "^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}$",
                code));
        Assert.Equal(FakeCodeProvider.Counter, store.Factor!.LastAcceptedCounter);
        Assert.All(
            store.RecoveryHashes,
            hash => Assert.Matches("^[0-9A-F]{64}$", hash));
        Assert.DoesNotContain(
            confirmed.Value.RecoveryCodes,
            code => store.RecoveryHashes.Contains(code));

        var method = new TotpVerificationMethodProvider<TestProfile>(
            store,
            codeProvider,
            new FakeSecretProtector());
        var context = new VerificationMethodContext(
            Guid.NewGuid(),
            user.Id,
            "hello:test",
            "binding");
        var issued = await method.IssueAsync(
            context,
            CancellationToken.None);

        Assert.False(await method.VerifyAsync(
            context,
            issued.Verifier,
            FakeCodeProvider.Code,
            CancellationToken.None));

        var recoveryCode = confirmed.Value.RecoveryCodes[0];
        Assert.True(await method.VerifyAsync(
            context,
            issued.Verifier,
            recoveryCode,
            CancellationToken.None));
        Assert.False(await method.VerifyAsync(
            context,
            issued.Verifier,
            recoveryCode,
            CancellationToken.None));
    }

    [Fact]
    public async Task EnrollmentConfirmationIsRateLimitedByAccountAndClient()
    {
        var user = CreateUser();
        var limiter = new RecordingRateLimiter();
        var service = new IdentityTotpService<TestProfile>(
            new FakeFactorStore(),
            new FakeUserStore(user),
            new FakeCodeProvider(),
            new FakeSecretProtector(),
            new TotpOptions(),
            new IdentityRateLimitOptions(),
            [limiter],
            new NoopIdentityMetrics());

        var begun = await service.BeginEnrollmentAsync(
            new BeginTotpEnrollmentCommand(user.Id, "client-a"),
            CancellationToken.None);
        Assert.True(begun.IsSuccess);
        var confirmed = await service.ConfirmEnrollmentAsync(
            new ConfirmTotpEnrollmentCommand(
                user.Id,
                begun.Value.EnrollmentId,
                FakeCodeProvider.Code,
                "client-a"),
            CancellationToken.None);

        Assert.True(confirmed.IsSuccess);
        Assert.Contains(
            limiter.Requests,
            request => request.Scope == "verification.response.client"
                && request.Key == "client-a");
        Assert.Contains(
            limiter.Requests,
            request => request.Scope == "verification.response.account"
                && request.Key == user.Id.ToString("N"));
    }

    private static IdentityUser<TestProfile> CreateUser()
    {
        var now = DateTimeOffset.UtcNow;
        return new IdentityUser<TestProfile>(
            Guid.NewGuid(),
            UserFlags.None,
            "alice",
            "alice@example.test",
            true,
            null,
            false,
            new TestProfile("Alice"),
            1,
            "STAMP",
            null,
            null,
            null,
            now,
            now);
    }

    private sealed record TestProfile(string DisplayName);

    private sealed class FakeCodeProvider : ITotpCodeProvider
    {
        public const string Secret =
            "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
        public const string Code = "123456";
        public const long Counter = 42;

        public string CreateSecret() => Secret;

        public bool TryMatchCounter(
            string secret,
            string response,
            DateTimeOffset now,
            long? minimumExclusiveCounter,
            out long counter)
        {
            counter = Counter;
            return secret == Secret
                && response == Code
                && (minimumExclusiveCounter is null
                    || Counter > minimumExclusiveCounter);
        }
    }

    private sealed class FakeSecretProtector : ITotpSecretProtector
    {
        public string Protect(string secret) => $"protected:{secret}";

        public bool TryUnprotect(string protectedSecret, out string secret)
        {
            const string prefix = "protected:";
            if (protectedSecret.StartsWith(prefix, StringComparison.Ordinal))
            {
                secret = protectedSecret[prefix.Length..];
                return true;
            }

            secret = string.Empty;
            return false;
        }
    }

    private sealed class FakeFactorStore : ITotpFactorStore<TestProfile>
    {
        public StoredTotpFactor? Factor { get; private set; }
        public HashSet<string> RecoveryHashes { get; } =
            new(StringComparer.Ordinal);

        public Task<StoredTotpFactor?> FindByUserIdAsync(
            Guid userId,
            CancellationToken ct)
            => Task.FromResult(
                Factor?.UserId == userId ? Factor : null);

        public Task<OperationResult> CreateOrReplacePendingAsync(
            NewTotpEnrollment enrollment,
            DateTimeOffset now,
            CancellationToken ct)
        {
            Factor = new StoredTotpFactor(
                enrollment.UserId,
                enrollment.EnrollmentId,
                enrollment.ProtectedSecret,
                TotpFactorState.Pending,
                null,
                0,
                1,
                enrollment.ExpiresAt,
                null,
                now,
                now);
            RecoveryHashes.Clear();
            return Task.FromResult(OperationResultFactory.Success());
        }

        public Task<OperationResult<StoredTotpFactor>> EnableAsync(
            Guid userId,
            Guid enrollmentId,
            long expectedVersion,
            long initialAcceptedCounter,
            IReadOnlyCollection<string> recoveryCodeHashes,
            DateTimeOffset now,
            CancellationToken ct)
        {
            if (Factor is null
                || Factor.UserId != userId
                || Factor.EnrollmentId != enrollmentId
                || Factor.Version != expectedVersion)
            {
                return Task.FromResult(
                    OperationResultFactory.Fail<StoredTotpFactor>(
                        new Error(
                            "test.concurrency",
                            "Concurrency conflict.",
                            ErrorType.Conflict)));
            }

            RecoveryHashes.UnionWith(recoveryCodeHashes);
            Factor = Factor with
            {
                State = TotpFactorState.Enabled,
                LastAcceptedCounter = initialAcceptedCounter,
                RecoveryCodesRemaining = RecoveryHashes.Count,
                Version = Factor.Version + 1,
                PendingExpiresAt = null,
                EnabledAt = now,
                ModifiedAt = now,
            };
            return Task.FromResult(
                OperationResultFactory.Success(Factor));
        }

        public Task<OperationResult> DisableAsync(
            Guid userId,
            DateTimeOffset now,
            CancellationToken ct)
        {
            Factor = null;
            RecoveryHashes.Clear();
            return Task.FromResult(OperationResultFactory.Success());
        }

        public Task<OperationResult<bool>> TryAcceptCounterAsync(
            Guid userId,
            Guid enrollmentId,
            long expectedVersion,
            long counter,
            DateTimeOffset now,
            CancellationToken ct)
        {
            var accepted = Factor is not null
                && Factor.UserId == userId
                && Factor.EnrollmentId == enrollmentId
                && Factor.Version == expectedVersion
                && (Factor.LastAcceptedCounter is null
                    || counter > Factor.LastAcceptedCounter);
            if (accepted)
            {
                Factor = Factor! with
                {
                    LastAcceptedCounter = counter,
                    Version = Factor.Version + 1,
                    ModifiedAt = now,
                };
            }

            return Task.FromResult(
                OperationResultFactory.Success(accepted));
        }

        public Task<OperationResult<bool>> TryConsumeRecoveryCodeAsync(
            Guid userId,
            Guid enrollmentId,
            string recoveryCodeHash,
            DateTimeOffset now,
            CancellationToken ct)
        {
            var consumed = Factor?.UserId == userId
                && Factor.EnrollmentId == enrollmentId
                && RecoveryHashes.Remove(recoveryCodeHash);
            if (consumed)
            {
                Factor = Factor! with
                {
                    RecoveryCodesRemaining = RecoveryHashes.Count,
                    ModifiedAt = now,
                };
            }

            return Task.FromResult(
                OperationResultFactory.Success(consumed));
        }
    }

    private sealed class FakeUserStore(IdentityUser<TestProfile> user)
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

    private sealed class RecordingRateLimiter
        : IIdentityRateLimiter<TestProfile>
    {
        public List<RateLimitRequest> Requests { get; } = [];

        public Task<RateLimitDecision> CheckAsync(
            RateLimitRequest request,
            CancellationToken ct)
            => Task.FromResult(
                new RateLimitDecision(IsAllowed: true, RetryAfter: null));

        public Task<RateLimitDecision> HitAsync(
            RateLimitRequest request,
            CancellationToken ct)
        {
            Requests.Add(request);
            return Task.FromResult(
                new RateLimitDecision(IsAllowed: true, RetryAfter: null));
        }

        public Task ResetAsync(
            string scope,
            string key,
            CancellationToken ct)
            => Task.CompletedTask;

        public Task<int> PruneAsync(CancellationToken ct)
            => Task.FromResult(0);
    }
}
