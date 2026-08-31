using Skopka.Abstraction.OperationResult;
using Skopka.Identity.DeviceAuthorization;
using Skopka.Identity.Errors;
using Skopka.Identity.Metrics;
using Skopka.Identity.Sessions;
using Skopka.Identity.StepUp;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Handles;
using Skopka.Identity.Verification;
using Xunit;

namespace Skopka.Identity.Core.Tests;

public sealed class IdentityDeviceAuthorizationServiceTests
{
    [Fact]
    public async Task ApprovalAndConsumeCreateOneIndependentSession()
    {
        var fixture = new Fixture();
        var created = await fixture.CreateAsync();

        var approved = await fixture.Service.ApproveAsync(
            fixture.Approve(created),
            CancellationToken.None);
        var consumed = await fixture.Service.ConsumeAsync(
            new ConsumeDeviceAuthorizationRequestCommand(
                created.DeviceCode,
                created.BrowserVerifier),
            CancellationToken.None);

        Assert.True(approved.IsSuccess);
        Assert.True(consumed.IsSuccess);
        Assert.Equal(1, fixture.Sessions.CreateCount);
        Assert.Equal(
            DeviceAuthorizationState.Consumed,
            fixture.Store.Request!.State);
        Assert.Equal(
            consumed.Value.Session.SessionId,
            fixture.Store.Request.SessionId);
    }

    [Fact]
    public async Task ApprovalRequiresFreshMatchingTotpStepUp()
    {
        var fixture = new Fixture();
        var created = await fixture.CreateAsync();
        var invalidDecision = fixture.Decision(created) with
        {
            Method = VerificationMethods.OneTimeCode,
        };

        var result = await fixture.Service.ApproveAsync(
            new ApproveDeviceAuthorizationRequestCommand(
                created.DeviceCode,
                fixture.UserStore.User.Id,
                invalidDecision),
            CancellationToken.None);

        AssertError(
            result,
            IdentityErrorCodes.DeviceAuthorizationStepUpInvalid);
        Assert.Equal(
            DeviceAuthorizationState.Pending,
            fixture.Store.Request!.State);
    }

    [Fact]
    public async Task ApprovedRequestCannotBeApprovedAgain()
    {
        var fixture = new Fixture();
        var created = await fixture.CreateAsync();

        var first = await fixture.Service.ApproveAsync(
            fixture.Approve(created),
            CancellationToken.None);
        var repeated = await fixture.Service.ApproveAsync(
            fixture.Approve(created),
            CancellationToken.None);

        Assert.True(first.IsSuccess);
        AssertError(
            repeated,
            IdentityErrorCodes.DeviceAuthorizationStateInvalid);
        Assert.Equal(
            DeviceAuthorizationState.Approved,
            fixture.Store.Request!.State);
    }

    [Fact]
    public async Task DeniedRequestCannotBeConsumedOrApprovedAgain()
    {
        var fixture = new Fixture();
        var created = await fixture.CreateAsync();
        var denied = await fixture.Service.DenyAsync(
            new DenyDeviceAuthorizationRequestCommand(
                created.DeviceCode,
                fixture.UserStore.User.Id),
            CancellationToken.None);

        var consumed = await fixture.Service.ConsumeAsync(
            new ConsumeDeviceAuthorizationRequestCommand(
                created.DeviceCode,
                created.BrowserVerifier),
            CancellationToken.None);
        var approved = await fixture.Service.ApproveAsync(
            fixture.Approve(created),
            CancellationToken.None);

        Assert.True(denied.IsSuccess);
        AssertError(
            consumed,
            IdentityErrorCodes.DeviceAuthorizationStateInvalid);
        AssertError(
            approved,
            IdentityErrorCodes.DeviceAuthorizationStateInvalid);
        Assert.Equal(0, fixture.Sessions.CreateCount);
    }

    [Fact]
    public async Task WrongBrowserVerifierIsRejected()
    {
        var fixture = new Fixture();
        var created = await fixture.CreateAsync();
        Assert.True((await fixture.Service.ApproveAsync(
            fixture.Approve(created),
            CancellationToken.None)).IsSuccess);

        var result = await fixture.Service.ConsumeAsync(
            new ConsumeDeviceAuthorizationRequestCommand(
                created.DeviceCode,
                "wrong-verifier"),
            CancellationToken.None);

        AssertError(
            result,
            IdentityErrorCodes.DeviceAuthorizationVerifierInvalid);
        Assert.Equal(0, fixture.Sessions.CreateCount);
    }

    [Fact]
    public async Task ApprovalDetailsCanBeFoundByNormalizedUserCode()
    {
        var fixture = new Fixture();
        var created = await fixture.CreateAsync();
        var enteredCode = created.UserCode
            .Replace('-', ' ')
            .ToLowerInvariant();

        var result = await fixture.Service
            .GetApprovalDetailsByUserCodeAsync(
                new GetDeviceAuthorizationApprovalDetailsByUserCodeCommand(
                    enteredCode),
                CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal(created.DeviceCode, result.Value.DeviceCode);
        Assert.Equal(created.UserCode, result.Value.UserCode);
    }

    [Fact]
    public async Task UnknownUserCodeUsesGenericInvalidError()
    {
        var fixture = new Fixture();
        await fixture.CreateAsync();

        var result = await fixture.Service
            .GetApprovalDetailsByUserCodeAsync(
                new GetDeviceAuthorizationApprovalDetailsByUserCodeCommand(
                    "ZZZZ-ZZZZ"),
                CancellationToken.None);

        AssertError(result, IdentityErrorCodes.DeviceAuthorizationInvalid);
    }

    [Fact]
    public async Task SecurityStampChangeAfterApprovalRejectsConsume()
    {
        var fixture = new Fixture();
        var created = await fixture.CreateAsync();
        Assert.True((await fixture.Service.ApproveAsync(
            fixture.Approve(created),
            CancellationToken.None)).IsSuccess);
        fixture.UserStore.User = fixture.UserStore.User with
        {
            SecurityStamp = "changed-stamp",
        };

        var result = await fixture.Service.ConsumeAsync(
            new ConsumeDeviceAuthorizationRequestCommand(
                created.DeviceCode,
                created.BrowserVerifier),
            CancellationToken.None);

        AssertError(result, IdentityErrorCodes.DeviceAuthorizationInvalid);
        Assert.Equal(0, fixture.Sessions.CreateCount);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task DeletedOrBlockedApproverCannotConsume(
        bool deleted,
        bool blocked)
    {
        var fixture = new Fixture();
        var created = await fixture.CreateAsync();
        Assert.True((await fixture.Service.ApproveAsync(
            fixture.Approve(created),
            CancellationToken.None)).IsSuccess);
        fixture.UserStore.User = fixture.UserStore.User with
        {
            DeletedAt = deleted ? DateTimeOffset.UtcNow : null,
            BlockedAt = blocked ? DateTimeOffset.UtcNow : null,
            BlockedUntil = null,
        };

        var result = await fixture.Service.ConsumeAsync(
            new ConsumeDeviceAuthorizationRequestCommand(
                created.DeviceCode,
                created.BrowserVerifier),
            CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Equal(0, fixture.Sessions.CreateCount);
    }

    [Fact]
    public async Task ConcurrentConsumeCreatesExactlyOneSession()
    {
        var fixture = new Fixture(sessionDelay: TimeSpan.FromMilliseconds(30));
        var created = await fixture.CreateAsync();
        Assert.True((await fixture.Service.ApproveAsync(
            fixture.Approve(created),
            CancellationToken.None)).IsSuccess);
        var command = new ConsumeDeviceAuthorizationRequestCommand(
            created.DeviceCode,
            created.BrowserVerifier);

        var results = await Task.WhenAll(
            fixture.Service.ConsumeAsync(command, CancellationToken.None),
            fixture.Service.ConsumeAsync(command, CancellationToken.None));

        Assert.Single(results, result => result.IsSuccess);
        Assert.Equal(1, fixture.Sessions.CreateCount);
        Assert.Equal(
            DeviceAuthorizationState.Consumed,
            fixture.Store.Request!.State);
    }

    [Fact]
    public async Task FailedCompletionAndRevocationCannotReleaseConsumption()
    {
        var fixture = new Fixture(
            completeConsumeSucceeds: false,
            revokeCreatedSessionSucceeds: false);
        var created = await fixture.CreateAsync();
        Assert.True((await fixture.Service.ApproveAsync(
            fixture.Approve(created),
            CancellationToken.None)).IsSuccess);
        var command = new ConsumeDeviceAuthorizationRequestCommand(
            created.DeviceCode,
            created.BrowserVerifier);

        var first = await fixture.Service.ConsumeAsync(
            command,
            CancellationToken.None);
        var retry = await fixture.Service.ConsumeAsync(
            command,
            CancellationToken.None);

        Assert.False(first.IsSuccess);
        Assert.False(retry.IsSuccess);
        Assert.Equal(1, fixture.Sessions.CreateCount);
        Assert.Equal(
            DeviceAuthorizationState.Consuming,
            fixture.Store.Request!.State);
    }

    [Fact]
    public async Task RequestExpiresAndCannotBeApproved()
    {
        var fixture = new Fixture(
            requestLifetime: TimeSpan.FromMilliseconds(1));
        var created = await fixture.CreateAsync();
        await Task.Delay(20);

        var status = await fixture.Service.GetStatusAsync(
            new GetDeviceAuthorizationStatusCommand(
                created.DeviceCode,
                created.BrowserVerifier),
            CancellationToken.None);
        var approved = await fixture.Service.ApproveAsync(
            fixture.Approve(created),
            CancellationToken.None);

        Assert.True(status.IsSuccess);
        Assert.Equal(DeviceAuthorizationState.Expired, status.Value.State);
        AssertError(
            approved,
            IdentityErrorCodes.DeviceAuthorizationStateInvalid);
    }

    private static void AssertError(
        OperationResult result,
        string code)
        => Assert.Contains(result.Errors, error => error.Code == code);

    private sealed class Fixture
    {
        public FakeStore Store { get; }
        public FakeUserStore UserStore { get; } = new(CreateUser());
        public FakeSessionService Sessions { get; }

        public IdentityDeviceAuthorizationService<TestProfile> Service
            { get; }

        public Fixture(
            TimeSpan? requestLifetime = null,
            TimeSpan? sessionDelay = null,
            bool completeConsumeSucceeds = true,
            bool revokeCreatedSessionSucceeds = true)
        {
            Store = new FakeStore(completeConsumeSucceeds);
            Sessions = new FakeSessionService(
                sessionDelay ?? TimeSpan.Zero,
                revokeCreatedSessionSucceeds);
            var options = new DeviceAuthorizationOptions();
            if (requestLifetime is not null)
            {
                options.RequestLifetime = requestLifetime.Value;
                options.StepUpMaximumAge = requestLifetime.Value;
            }

            Service = new IdentityDeviceAuthorizationService<TestProfile>(
                Store,
                UserStore,
                Sessions,
                options,
                new NoopIdentityMetrics(),
                []);
        }

        public async Task<CreatedDeviceAuthorizationRequest> CreateAsync()
        {
            var result = await Service.CreateAsync(
                new CreateDeviceAuthorizationRequestCommand(
                    new DeviceAuthorizationMetadata(
                        "127.0.0.1",
                        "Browser",
                        "Browser on OS",
                        "client",
                        "/connect/authorize?client_id=client",
                        new IdentitySessionMetadata(
                            "Hello",
                            "Browser on OS"))),
                CancellationToken.None);
            return result.Value;
        }

        public ApproveDeviceAuthorizationRequestCommand Approve(
            CreatedDeviceAuthorizationRequest created)
            => new(
                created.DeviceCode,
                UserStore.User.Id,
                Decision(created));

        public StepUpDecision Decision(
            CreatedDeviceAuthorizationRequest created)
        {
            var now = DateTimeOffset.UtcNow;
            return new StepUpDecision(
                UserStore.User.Id,
                DeviceAuthorizationActions.Approve,
                created.DeviceCode,
                "device-approval",
                Guid.NewGuid(),
                VerificationMethods.TimeBasedOneTimePassword,
                2,
                now,
                now);
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
                "security-stamp",
                null,
                null,
                null,
                now,
                now);
        }

    }

    private sealed class FakeStore(bool completeConsumeSucceeds)
        : IDeviceAuthorizationRequestStore<TestProfile>
    {
        private readonly SemaphoreSlim gate = new(1, 1);
        public StoredDeviceAuthorizationRequest? Request { get; private set; }

        public Task<OperationResult> CreateAsync(
            NewDeviceAuthorizationRequest request,
            DateTimeOffset now,
            CancellationToken ct)
        {
            Request = new StoredDeviceAuthorizationRequest(
                request.Id,
                request.DeviceCode,
                request.BrowserVerifierHash,
                request.UserCode,
                DeviceAuthorizationState.Pending,
                request.Metadata,
                null,
                null,
                null,
                null,
                1,
                now,
                request.ExpiresAt,
                now,
                null,
                null);
            return Task.FromResult(OperationResultFactory.Success());
        }

        public Task<StoredDeviceAuthorizationRequest?> FindByDeviceCodeAsync(
            string deviceCode,
            CancellationToken ct)
            => Task.FromResult(
                Request?.DeviceCode == deviceCode ? Request : null);

        public Task<IReadOnlyList<StoredDeviceAuthorizationRequest>>
            FindPendingByUserCodeAsync(
                string userCode,
                DateTimeOffset now,
                int maxCount,
                CancellationToken ct)
            => Task.FromResult<IReadOnlyList<
                StoredDeviceAuthorizationRequest>>(
                    Request is { State: DeviceAuthorizationState.Pending }
                        && Request.ExpiresAt > now
                        && Request.UserCode == userCode
                            ? [Request]
                            : []);

        public Task<OperationResult<StoredDeviceAuthorizationRequest>>
            ApproveAsync(
                Guid requestId,
                long expectedVersion,
                Guid userId,
                string securityStamp,
                DateTimeOffset now,
                CancellationToken ct)
            => TransitionAsync(
                expectedVersion,
                DeviceAuthorizationState.Pending,
                request => request with
                {
                    State = DeviceAuthorizationState.Approved,
                    ResolvedByUserId = userId,
                    ApprovedSecurityStamp = securityStamp,
                    ResolvedAt = now,
                },
                now,
                ct);

        public Task<OperationResult<StoredDeviceAuthorizationRequest>> DenyAsync(
            Guid requestId,
            long expectedVersion,
            Guid userId,
            DateTimeOffset now,
            CancellationToken ct)
            => TransitionAsync(
                expectedVersion,
                DeviceAuthorizationState.Pending,
                request => request with
                {
                    State = DeviceAuthorizationState.Denied,
                    ResolvedByUserId = userId,
                    ResolvedAt = now,
                },
                now,
                ct);

        public Task<OperationResult<StoredDeviceAuthorizationRequest>>
            BeginConsumeAsync(
                Guid requestId,
                long expectedVersion,
                Guid consumptionId,
                DateTimeOffset now,
                CancellationToken ct)
            => TransitionAsync(
                expectedVersion,
                DeviceAuthorizationState.Approved,
                request => request with
                {
                    State = DeviceAuthorizationState.Consuming,
                    ConsumptionId = consumptionId,
                },
                now,
                ct);

        public async Task<OperationResult> CompleteConsumeAsync(
            Guid requestId,
            Guid consumptionId,
            Guid sessionId,
            DateTimeOffset now,
            CancellationToken ct)
        {
            await gate.WaitAsync(ct);
            try
            {
                if (!completeConsumeSucceeds)
                {
                    return StateFailure();
                }

                if (Request is null
                    || Request.State != DeviceAuthorizationState.Consuming
                    || Request.ConsumptionId != consumptionId)
                {
                    return StateFailure();
                }

                Request = Request with
                {
                    State = DeviceAuthorizationState.Consumed,
                    SessionId = sessionId,
                    ConsumedAt = now,
                    ModifiedAt = now,
                    Version = Request.Version + 1,
                };
                return OperationResultFactory.Success();
            }
            finally
            {
                gate.Release();
            }
        }

        public async Task<OperationResult<StoredDeviceAuthorizationRequest>>
            ReleaseConsumeAsync(
                Guid requestId,
                Guid consumptionId,
                DateTimeOffset now,
                CancellationToken ct)
        {
            await gate.WaitAsync(ct);
            try
            {
                if (Request is null
                    || Request.State != DeviceAuthorizationState.Consuming
                    || Request.ConsumptionId != consumptionId)
                {
                    return StateFailure<StoredDeviceAuthorizationRequest>();
                }

                Request = Request with
                {
                    State = Request.ExpiresAt <= now
                        ? DeviceAuthorizationState.Expired
                        : DeviceAuthorizationState.Approved,
                    ConsumptionId = null,
                    ModifiedAt = now,
                    Version = Request.Version + 1,
                };
                return OperationResultFactory.Success(Request);
            }
            finally
            {
                gate.Release();
            }
        }

        public async Task<OperationResult<bool>> ExpireAsync(
            Guid requestId,
            long expectedVersion,
            DateTimeOffset now,
            CancellationToken ct)
        {
            await gate.WaitAsync(ct);
            try
            {
                if (Request is null
                    || Request.Version != expectedVersion
                    || Request.ExpiresAt > now
                    || Request.State is not (
                        DeviceAuthorizationState.Pending
                        or DeviceAuthorizationState.Approved))
                {
                    return OperationResultFactory.Success(false);
                }

                Request = Request with
                {
                    State = DeviceAuthorizationState.Expired,
                    ModifiedAt = now,
                    Version = Request.Version + 1,
                };
                return OperationResultFactory.Success(true);
            }
            finally
            {
                gate.Release();
            }
        }

        public Task<int> PruneAsync(
            DateTimeOffset expiredBefore,
            int maxCount,
            CancellationToken ct)
            => Task.FromResult(0);

        private async Task<OperationResult<StoredDeviceAuthorizationRequest>>
            TransitionAsync(
                long expectedVersion,
                DeviceAuthorizationState state,
                Func<StoredDeviceAuthorizationRequest,
                    StoredDeviceAuthorizationRequest> transition,
                DateTimeOffset now,
                CancellationToken ct)
        {
            await gate.WaitAsync(ct);
            try
            {
                if (Request is null
                    || Request.Version != expectedVersion
                    || Request.State != state
                    || Request.ExpiresAt <= now)
                {
                    return StateFailure<StoredDeviceAuthorizationRequest>();
                }

                Request = transition(Request) with
                {
                    ModifiedAt = now,
                    Version = Request.Version + 1,
                };
                return OperationResultFactory.Success(Request);
            }
            finally
            {
                gate.Release();
            }
        }

        private static OperationResult StateFailure()
            => OperationResultFactory.Fail(
                new Error(
                    IdentityErrorCodes.DeviceAuthorizationStateInvalid,
                    "Invalid state.",
                    ErrorType.Conflict));

        private static OperationResult<T> StateFailure<T>()
            => OperationResultFactory.Fail<T>(
                new Error(
                    IdentityErrorCodes.DeviceAuthorizationStateInvalid,
                    "Invalid state.",
                    ErrorType.Conflict));
    }

    private sealed class FakeSessionService(
        TimeSpan delay,
        bool revokeCreatedSessionSucceeds)
        : IIdentitySessionService<TestProfile>
    {
        private int createCount;
        public int CreateCount => createCount;

        public async Task<OperationResult<IssuedIdentitySession>> CreateAsync(
            CreateIdentitySessionCommand command,
            CancellationToken ct)
        {
            Interlocked.Increment(ref createCount);
            if (delay > TimeSpan.Zero)
            {
                await Task.Delay(delay, ct);
            }

            var now = DateTimeOffset.UtcNow;
            return OperationResultFactory.Success(
                new IssuedIdentitySession(
                    Guid.NewGuid(),
                    "access",
                    now.AddMinutes(15),
                    "refresh",
                    now.AddDays(1)));
        }

        public Task<OperationResult<IssuedIdentitySession>> RefreshAsync(
            RefreshIdentitySessionCommand command,
            CancellationToken ct) => throw new NotSupportedException();
        public Task<OperationResult<IdentityUser<TestProfile>>>
            ValidateAccessTokenAsync(string accessToken, CancellationToken ct)
            => throw new NotSupportedException();
        public Task<OperationResult> RevokeAsync(
            RevokeIdentitySessionCommand command,
            CancellationToken ct) => throw new NotSupportedException();
        public Task<OperationResult> RevokeByIdAsync(
            RevokeIdentitySessionByIdCommand command,
            CancellationToken ct)
            => Task.FromResult(
                revokeCreatedSessionSucceeds
                    ? OperationResultFactory.Success()
                    : OperationResultFactory.Fail(
                        new Error(
                            "session.revoke_failed",
                            "Session revocation failed.",
                            ErrorType.Failure)));
        public Task<OperationResult> RevokeAllAsync(
            RevokeAllIdentitySessionsCommand command,
            CancellationToken ct) => throw new NotSupportedException();
        public Task<OperationResult<IReadOnlyList<IdentitySessionInfo>>>
            ListAsync(
                ListIdentitySessionsCommand command,
                CancellationToken ct) => throw new NotSupportedException();
        public Task<int> PruneAsync(CancellationToken ct)
            => throw new NotSupportedException();
    }

    private sealed class FakeUserStore(IdentityUser<TestProfile> user)
        : IIdentityUserStore<TestProfile>
    {
        public IdentityUser<TestProfile> User { get; set; } = user;
        public Task<IdentityUser<TestProfile>?> FindByIdAsync(
            Guid id,
            CancellationToken ct)
            => Task.FromResult<IdentityUser<TestProfile>?>(
                id == User.Id ? User : null);
        public Task<OperationResult<IdentityUser<TestProfile>>> CreateAsync(
            NewIdentityUser<TestProfile> user,
            NormalizedHandles handles,
            DateTimeOffset now,
            CancellationToken ct) => throw new NotSupportedException();
        public Task<OperationResult<IdentityUser<TestProfile>>>
            UpdateHandlesAsync(
                Guid userId,
                long expectedVersion,
                UpdatedHandles updated,
                DateTimeOffset now,
                CancellationToken ct) => throw new NotSupportedException();
        public Task<OperationResult<IdentityUser<TestProfile>>>
            UpdateProfileAsync(
                Guid userId,
                long expectedVersion,
                TestProfile profile,
                DateTimeOffset now,
                CancellationToken ct) => throw new NotSupportedException();
        public Task<OperationResult<IdentityUser<TestProfile>>>
            UpdateSecurityStampAsync(
                Guid userId,
                long expectedVersion,
                string securityStamp,
                DateTimeOffset now,
                CancellationToken ct) => throw new NotSupportedException();
        public Task<OperationResult> UpdateStateAsync(
            Guid userId,
            long expectedVersion,
            DateTimeOffset? deletedAt,
            DateTimeOffset? blockedAt,
            DateTimeOffset? blockedUntil,
            string? newSecurityStamp,
            DateTimeOffset now,
            CancellationToken ct) => throw new NotSupportedException();
    }

    private sealed record TestProfile(string DisplayName);
}
