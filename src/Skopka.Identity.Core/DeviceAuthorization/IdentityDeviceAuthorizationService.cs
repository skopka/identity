using System.Security.Cryptography;
using System.Text;
using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Errors;
using Skopka.Identity.Metrics;
using Skopka.Identity.RateLimiting;
using Skopka.Identity.SecurityEvents;
using Skopka.Identity.Sessions;
using Skopka.Identity.Users;

namespace Skopka.Identity.DeviceAuthorization;

public sealed class IdentityDeviceAuthorizationService<TProfile>(
    IDeviceAuthorizationRequestStore<TProfile> requests,
    IIdentityUserStore<TProfile> users,
    IIdentitySessionService<TProfile> sessions,
    DeviceAuthorizationOptions options,
    IIdentityMetrics metrics,
    IEnumerable<IIdentityRateLimiter<TProfile>> rateLimiters,
    IIdentitySecurityEventObserver? securityEvents = null)
    : IIdentityDeviceAuthorizationService<TProfile>
{
    private const int RandomSecretSize = 32;
    private readonly IIdentityRateLimiter<TProfile>? rateLimiter =
        rateLimiters.FirstOrDefault();

    public async Task<OperationResult<CreatedDeviceAuthorizationRequest>>
        CreateAsync(
            CreateDeviceAuthorizationRequestCommand command,
            CancellationToken ct)
    {
        using var op = metrics.Begin("device_authorization.create");
        ValidateOptions();
        ArgumentNullException.ThrowIfNull(command);

        var metadata = NormalizeMetadata(command.Metadata);
        if (!metadata.IsSuccess)
        {
            return Fail<CreatedDeviceAuthorizationRequest>(op, metadata.Errors);
        }

        var rateLimitError = await CheckRateLimitAsync(
            IdentityRateLimitScopes.DeviceAuthorizationCreateClient,
            NormalizeClientKey(command.ClientKey),
            options.CreateClientPermitLimit,
            options.CreateClientWindow,
            ct);
        if (rateLimitError is not null)
        {
            return Fail<CreatedDeviceAuthorizationRequest>(op, rateLimitError);
        }

        var now = DateTimeOffset.UtcNow;
        var id = Guid.NewGuid();
        var deviceCode = GenerateSecret();
        var browserVerifier = GenerateSecret();
        var userCode = GenerateUserCode();
        var expiresAt = now.Add(options.RequestLifetime);
        var created = await requests.CreateAsync(
            new NewDeviceAuthorizationRequest(
                id,
                deviceCode,
                Hash(browserVerifier),
                userCode,
                metadata.Value,
                expiresAt),
            now,
            ct);
        if (!created.IsSuccess)
        {
            return Fail<CreatedDeviceAuthorizationRequest>(op, created.Errors);
        }

        securityEvents.Observe(
            IdentitySecurityEventTypes.DeviceAuthorizationCreated,
            now,
            userId: null,
            id);
        op.Success();
        return OperationResultFactory.Success(
            new CreatedDeviceAuthorizationRequest(
                id,
                deviceCode,
                browserVerifier,
                userCode,
                now,
                expiresAt));
    }

    public async Task<OperationResult<DeviceAuthorizationStatus>>
        GetStatusAsync(
            GetDeviceAuthorizationStatusCommand command,
            CancellationToken ct)
    {
        using var op = metrics.Begin("device_authorization.status");
        ValidateOptions();
        ArgumentNullException.ThrowIfNull(command);

        if (!IsValidDeviceCode(command.DeviceCode)
            || !IsValidBrowserVerifier(command.BrowserVerifier))
        {
            return Fail<DeviceAuthorizationStatus>(
                op,
                DeviceAuthorizationErrors.Invalid());
        }

        var rateLimitError = await CheckRateLimitAsync(
            IdentityRateLimitScopes.DeviceAuthorizationStatusClient,
            NormalizeClientKey(command.ClientKey),
            options.StatusClientPermitLimit,
            options.StatusClientWindow,
            ct);
        if (rateLimitError is not null)
        {
            return Fail<DeviceAuthorizationStatus>(op, rateLimitError);
        }

        var request = await requests.FindByDeviceCodeAsync(
            command.DeviceCode,
            ct);
        if (request is null)
        {
            return Fail<DeviceAuthorizationStatus>(
                op,
                DeviceAuthorizationErrors.Invalid());
        }

        if (!FixedTimeHashEquals(
                request.BrowserVerifierHash,
                command.BrowserVerifier))
        {
            return Fail<DeviceAuthorizationStatus>(
                op,
                DeviceAuthorizationErrors.VerifierInvalid());
        }

        request = await ExpireIfRequiredAsync(request, ct);
        op.Success();
        return OperationResultFactory.Success(ToStatus(request));
    }

    public async Task<OperationResult<DeviceAuthorizationApprovalDetails>>
        GetApprovalDetailsAsync(
            GetDeviceAuthorizationApprovalDetailsCommand command,
            CancellationToken ct)
    {
        using var op = metrics.Begin("device_authorization.approval_details");
        ValidateOptions();
        ArgumentNullException.ThrowIfNull(command);

        if (!IsValidDeviceCode(command.DeviceCode))
        {
            return Fail<DeviceAuthorizationApprovalDetails>(
                op,
                DeviceAuthorizationErrors.Invalid());
        }

        var rateLimitError = await CheckRateLimitAsync(
            IdentityRateLimitScopes.DeviceAuthorizationStatusClient,
            NormalizeClientKey(command.ClientKey),
            options.StatusClientPermitLimit,
            options.StatusClientWindow,
            ct);
        if (rateLimitError is not null)
        {
            return Fail<DeviceAuthorizationApprovalDetails>(op, rateLimitError);
        }

        var request = await requests.FindByDeviceCodeAsync(
            command.DeviceCode,
            ct);
        if (request is null)
        {
            return Fail<DeviceAuthorizationApprovalDetails>(
                op,
                DeviceAuthorizationErrors.Invalid());
        }

        request = await ExpireIfRequiredAsync(request, ct);
        if (request.State != DeviceAuthorizationState.Pending)
        {
            return Fail<DeviceAuthorizationApprovalDetails>(
                op,
                DeviceAuthorizationErrors.StateInvalid());
        }

        op.Success();
        return OperationResultFactory.Success(
            new DeviceAuthorizationApprovalDetails(
                request.Id,
                request.DeviceCode,
                request.UserCode,
                request.State,
                request.CreatedAt,
                request.ExpiresAt,
                request.Metadata.IpAddress,
                request.Metadata.UserAgent,
                request.Metadata.DeviceDisplayName));
    }

    public async Task<OperationResult> ApproveAsync(
        ApproveDeviceAuthorizationRequestCommand command,
        CancellationToken ct)
    {
        using var op = metrics.Begin("device_authorization.approve");
        ValidateOptions();
        ArgumentNullException.ThrowIfNull(command);

        if (!IsValidDeviceCode(command.DeviceCode)
            || command.UserId == Guid.Empty
            || !IsValidStepUp(command))
        {
            return Fail(op, DeviceAuthorizationErrors.StepUpInvalid());
        }

        var request = await requests.FindByDeviceCodeAsync(
            command.DeviceCode,
            ct);
        if (request is null)
        {
            return Fail(op, DeviceAuthorizationErrors.Invalid());
        }

        request = await ExpireIfRequiredAsync(request, ct);
        if (request.State != DeviceAuthorizationState.Pending)
        {
            return Fail(op, DeviceAuthorizationErrors.StateInvalid());
        }

        var now = DateTimeOffset.UtcNow;
        var user = await users.FindByIdAsync(command.UserId, ct);
        var userError = ValidateActiveUser(user, now);
        if (userError is not null)
        {
            return Fail(op, userError);
        }

        var approved = await requests.ApproveAsync(
            request.Id,
            request.Version,
            user!.Id,
            user.SecurityStamp,
            now,
            ct);
        if (!approved.IsSuccess)
        {
            return Fail(op, approved.Errors);
        }

        securityEvents.Observe(
            IdentitySecurityEventTypes.DeviceAuthorizationApproved,
            now,
            user.Id,
            request.Id);
        op.Success();
        return OperationResultFactory.Success();
    }

    public async Task<OperationResult> DenyAsync(
        DenyDeviceAuthorizationRequestCommand command,
        CancellationToken ct)
    {
        using var op = metrics.Begin("device_authorization.deny");
        ValidateOptions();
        ArgumentNullException.ThrowIfNull(command);

        if (!IsValidDeviceCode(command.DeviceCode)
            || command.UserId == Guid.Empty)
        {
            return Fail(op, DeviceAuthorizationErrors.Invalid());
        }

        var request = await requests.FindByDeviceCodeAsync(
            command.DeviceCode,
            ct);
        if (request is null)
        {
            return Fail(op, DeviceAuthorizationErrors.Invalid());
        }

        request = await ExpireIfRequiredAsync(request, ct);
        if (request.State != DeviceAuthorizationState.Pending)
        {
            return Fail(op, DeviceAuthorizationErrors.StateInvalid());
        }

        var now = DateTimeOffset.UtcNow;
        var user = await users.FindByIdAsync(command.UserId, ct);
        var userError = ValidateActiveUser(user, now);
        if (userError is not null)
        {
            return Fail(op, userError);
        }

        var denied = await requests.DenyAsync(
            request.Id,
            request.Version,
            user!.Id,
            now,
            ct);
        if (!denied.IsSuccess)
        {
            return Fail(op, denied.Errors);
        }

        securityEvents.Observe(
            IdentitySecurityEventTypes.DeviceAuthorizationDenied,
            now,
            user.Id,
            request.Id);
        op.Success();
        return OperationResultFactory.Success();
    }

    public async Task<OperationResult<ConsumedDeviceAuthorizationRequest>>
        ConsumeAsync(
            ConsumeDeviceAuthorizationRequestCommand command,
            CancellationToken ct)
    {
        using var op = metrics.Begin("device_authorization.consume");
        ValidateOptions();
        ArgumentNullException.ThrowIfNull(command);

        if (!IsValidDeviceCode(command.DeviceCode)
            || !IsValidBrowserVerifier(command.BrowserVerifier))
        {
            return Fail<ConsumedDeviceAuthorizationRequest>(
                op,
                DeviceAuthorizationErrors.Invalid());
        }

        var request = await requests.FindByDeviceCodeAsync(
            command.DeviceCode,
            ct);
        if (request is null)
        {
            return Fail<ConsumedDeviceAuthorizationRequest>(
                op,
                DeviceAuthorizationErrors.Invalid());
        }

        if (!FixedTimeHashEquals(
                request.BrowserVerifierHash,
                command.BrowserVerifier))
        {
            return Fail<ConsumedDeviceAuthorizationRequest>(
                op,
                DeviceAuthorizationErrors.VerifierInvalid());
        }

        request = await ExpireIfRequiredAsync(request, ct);
        if (request.State != DeviceAuthorizationState.Approved
            || request.ResolvedByUserId is null
            || string.IsNullOrWhiteSpace(request.ApprovedSecurityStamp))
        {
            return Fail<ConsumedDeviceAuthorizationRequest>(
                op,
                DeviceAuthorizationErrors.StateInvalid());
        }

        var now = DateTimeOffset.UtcNow;
        var user = await users.FindByIdAsync(
            request.ResolvedByUserId.Value,
            ct);
        var userError = ValidateActiveUser(user, now);
        if (userError is not null
            || !FixedTimeEquals(
                user!.SecurityStamp,
                request.ApprovedSecurityStamp))
        {
            return Fail<ConsumedDeviceAuthorizationRequest>(
                op,
                userError ?? DeviceAuthorizationErrors.Invalid());
        }

        var consumptionId = Guid.NewGuid();
        var claimed = await requests.BeginConsumeAsync(
            request.Id,
            request.Version,
            consumptionId,
            now,
            ct);
        if (!claimed.IsSuccess)
        {
            return Fail<ConsumedDeviceAuthorizationRequest>(
                op,
                DeviceAuthorizationErrors.StateInvalid());
        }

        var issued = await sessions.CreateAsync(
            new CreateIdentitySessionCommand(
                user.Id,
                request.ApprovedSecurityStamp,
                request.Metadata.SessionMetadata),
            ct);
        if (!issued.IsSuccess)
        {
            await requests.ReleaseConsumeAsync(
                request.Id,
                consumptionId,
                DateTimeOffset.UtcNow,
                ct);
            return Fail<ConsumedDeviceAuthorizationRequest>(op, issued.Errors);
        }

        var completedAt = DateTimeOffset.UtcNow;
        var completed = await requests.CompleteConsumeAsync(
            request.Id,
            consumptionId,
            issued.Value.SessionId,
            completedAt,
            ct);
        if (!completed.IsSuccess)
        {
            var revoked = await sessions.RevokeByIdAsync(
                new RevokeIdentitySessionByIdCommand(
                    user.Id,
                    issued.Value.SessionId),
                ct);
            if (revoked.IsSuccess)
            {
                await requests.ReleaseConsumeAsync(
                    request.Id,
                    consumptionId,
                    completedAt,
                    ct);
            }

            return Fail<ConsumedDeviceAuthorizationRequest>(
                op,
                completed.Errors);
        }

        securityEvents.Observe(
            IdentitySecurityEventTypes.DeviceAuthorizationConsumed,
            completedAt,
            user.Id,
            request.Id);
        op.Success();
        return OperationResultFactory.Success(
            new ConsumedDeviceAuthorizationRequest(
                issued.Value,
                request.Metadata.ClientId,
                request.Metadata.ReturnUrl));
    }

    public Task<int> PruneAsync(CancellationToken ct)
    {
        ValidateOptions();
        return requests.PruneAsync(
            DateTimeOffset.UtcNow.Subtract(
                options.RetentionAfterExpiration),
            options.CleanupBatchSize,
            ct);
    }

    private async Task<StoredDeviceAuthorizationRequest>
        ExpireIfRequiredAsync(
            StoredDeviceAuthorizationRequest request,
            CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        if (request.ExpiresAt > now
            || request.State is not (
                DeviceAuthorizationState.Pending
                or DeviceAuthorizationState.Approved))
        {
            return request;
        }

        var expired = await requests.ExpireAsync(
            request.Id,
            request.Version,
            now,
            ct);
        if (expired.IsSuccess && expired.Value)
        {
            securityEvents.Observe(
                IdentitySecurityEventTypes.DeviceAuthorizationExpired,
                now,
                request.ResolvedByUserId,
                request.Id);
        }

        return await requests.FindByDeviceCodeAsync(
                request.DeviceCode,
                ct)
            ?? request;
    }

    private bool IsValidStepUp(
        ApproveDeviceAuthorizationRequestCommand command)
    {
        var decision = command.StepUpDecision;
        if (decision is null
            || decision.UserId != command.UserId
            || !string.Equals(
                decision.Action,
                DeviceAuthorizationActions.Approve,
                StringComparison.Ordinal)
            || !string.Equals(
                decision.Binding,
                command.DeviceCode,
                StringComparison.Ordinal)
            || !string.Equals(
                decision.Method,
                options.RequiredStepUpMethod,
                StringComparison.Ordinal))
        {
            return false;
        }

        var now = DateTimeOffset.UtcNow;
        return decision.VerifiedAt <= decision.DecidedAt
            && decision.DecidedAt <= now
            && now - decision.VerifiedAt <= options.StepUpMaximumAge;
    }

    private async Task<Error?> CheckRateLimitAsync(
        string scope,
        string? clientKey,
        int permitLimit,
        TimeSpan window,
        CancellationToken ct)
    {
        if (rateLimiter is null || clientKey is null)
        {
            return null;
        }

        var decision = await rateLimiter.HitAsync(
            new RateLimitRequest(scope, clientKey, permitLimit, window),
            ct);
        return decision.IsAllowed
            ? null
            : IdentityRateLimitErrors.Exceeded(decision.RetryAfter);
    }

    private static OperationResult<DeviceAuthorizationMetadata>
        NormalizeMetadata(DeviceAuthorizationMetadata? metadata)
    {
        if (metadata is null)
        {
            return OperationResultFactory.Fail<DeviceAuthorizationMetadata>(
                IdentityErrors.Validation(
                    "metadata",
                    "Device authorization metadata is required."));
        }

        var values = new (string? Value, int Limit, string Field)[]
        {
            (metadata.IpAddress,
                DeviceAuthorizationLimits.MaximumIpAddressLength,
                "metadata.ipAddress"),
            (metadata.UserAgent,
                DeviceAuthorizationLimits.MaximumUserAgentLength,
                "metadata.userAgent"),
            (metadata.DeviceDisplayName,
                DeviceAuthorizationLimits.MaximumDeviceDisplayNameLength,
                "metadata.deviceDisplayName"),
            (metadata.ClientId,
                DeviceAuthorizationLimits.MaximumClientIdLength,
                "metadata.clientId"),
            (metadata.ReturnUrl,
                DeviceAuthorizationLimits.MaximumReturnUrlLength,
                "metadata.returnUrl"),
        };
        var normalized = new string?[values.Length];
        for (var index = 0; index < values.Length; index++)
        {
            var result = NormalizeLabel(values[index]);
            if (!result.IsSuccess)
            {
                return OperationResultFactory.Fail<DeviceAuthorizationMetadata>(
                    result.Errors);
            }

            normalized[index] = result.Value;
        }

        return OperationResultFactory.Success(
            new DeviceAuthorizationMetadata(
                normalized[0],
                normalized[1],
                normalized[2],
                normalized[3],
                normalized[4],
                metadata.SessionMetadata));
    }

    private static OperationResult<string?> NormalizeLabel(
        (string? Value, int Limit, string Field) input)
    {
        if (string.IsNullOrWhiteSpace(input.Value))
        {
            return OperationResultFactory.Success<string?>(null);
        }

        var normalized = input.Value.Trim();
        return normalized.Length <= input.Limit
            && !normalized.Any(char.IsControl)
                ? OperationResultFactory.Success<string?>(normalized)
                : OperationResultFactory.Fail<string?>(
                    IdentityErrors.Validation(
                        input.Field,
                        $"The value cannot exceed {input.Limit} non-control characters."));
    }

    private static Error? ValidateActiveUser(
        IdentityUser<TProfile>? user,
        DateTimeOffset now)
    {
        if (user is null)
        {
            return IdentityErrors.NotFound();
        }

        if (user.DeletedAt is not null)
        {
            return IdentityErrors.Deleted();
        }

        return user.BlockedAt is not null
            && (user.BlockedUntil is null || user.BlockedUntil > now)
                ? new Error(
                    IdentityErrorCodes.AuthenticationBlocked,
                    "Authentication is blocked.",
                    ErrorType.Forbidden)
                : null;
    }

    private void ValidateOptions()
    {
        if (options.RequestLifetime <= TimeSpan.Zero
            || options.RequestLifetime > TimeSpan.FromMinutes(15)
            || options.UserCodeLength < 4
            || options.UserCodeLength
                > DeviceAuthorizationLimits.MaximumUserCodeLength
            || options.UserCodeGroupSize < 0
            || options.UserCodeGroupSize > options.UserCodeLength
            || string.IsNullOrWhiteSpace(options.UserCodeAlphabet)
            || options.UserCodeAlphabet.Length < 16
            || options.UserCodeAlphabet.Length
                > DeviceAuthorizationLimits.MaximumUserCodeAlphabetLength
            || options.UserCodeAlphabet.Distinct().Count()
                != options.UserCodeAlphabet.Length
            || options.UserCodeAlphabet.Any(character =>
                char.IsWhiteSpace(character)
                || char.IsControl(character)
                || character == '-')
            || string.IsNullOrWhiteSpace(options.RequiredStepUpMethod)
            || options.StepUpMaximumAge <= TimeSpan.Zero
            || options.StepUpMaximumAge > options.RequestLifetime
            || options.CreateClientPermitLimit <= 0
            || options.CreateClientWindow <= TimeSpan.Zero
            || options.StatusClientPermitLimit <= 0
            || options.StatusClientWindow <= TimeSpan.Zero
            || options.RetentionAfterExpiration < TimeSpan.Zero
            || options.CleanupBatchSize <= 0)
        {
            throw new InvalidOperationException(
                "Device authorization options are invalid.");
        }
    }

    private string GenerateUserCode()
    {
        var characters = new char[options.UserCodeLength];
        for (var index = 0; index < characters.Length; index++)
        {
            characters[index] = options.UserCodeAlphabet[
                RandomNumberGenerator.GetInt32(
                    options.UserCodeAlphabet.Length)];
        }

        if (options.UserCodeGroupSize == 0
            || options.UserCodeGroupSize >= characters.Length)
        {
            return new string(characters);
        }

        return string.Join(
            '-',
            characters
                .Chunk(options.UserCodeGroupSize)
                .Select(group => new string(group)));
    }

    private static string GenerateSecret()
        => Convert.ToBase64String(
                RandomNumberGenerator.GetBytes(RandomSecretSize))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static string Hash(string value)
        => Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static bool FixedTimeHashEquals(
        string expectedHash,
        string verifier)
        => FixedTimeEquals(expectedHash, Hash(verifier));

    private static bool FixedTimeEquals(string expected, string provided)
    {
        var expectedBytes = Encoding.UTF8.GetBytes(expected);
        var providedBytes = Encoding.UTF8.GetBytes(provided);
        try
        {
            return CryptographicOperations.FixedTimeEquals(
                expectedBytes,
                providedBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedBytes);
            CryptographicOperations.ZeroMemory(providedBytes);
        }
    }

    private static bool IsValidDeviceCode(string? value)
        => !string.IsNullOrWhiteSpace(value)
            && value.Length
                <= DeviceAuthorizationLimits.MaximumDeviceCodeLength;

    private static bool IsValidBrowserVerifier(string? value)
        => !string.IsNullOrWhiteSpace(value)
            && value.Length
                <= DeviceAuthorizationLimits.MaximumBrowserVerifierLength;

    private static string? NormalizeClientKey(string? clientKey)
        => string.IsNullOrWhiteSpace(clientKey)
            ? null
            : clientKey.Trim();

    private static DeviceAuthorizationStatus ToStatus(
        StoredDeviceAuthorizationRequest request)
        => new(
            request.State,
            request.UserCode,
            request.CreatedAt,
            request.ExpiresAt,
            request.ResolvedAt);

    private static OperationResult Fail(
        IIdentityOpScope op,
        Error error)
    {
        op.Failure(error.Code);
        return OperationResultFactory.Fail(error);
    }

    private static OperationResult Fail(
        IIdentityOpScope op,
        IReadOnlyCollection<Error> errors)
    {
        op.Failure(errors.First().Code);
        return OperationResultFactory.Fail(errors);
    }

    private static OperationResult<T> Fail<T>(
        IIdentityOpScope op,
        Error error)
    {
        op.Failure(error.Code);
        return OperationResultFactory.Fail<T>(error);
    }

    private static OperationResult<T> Fail<T>(
        IIdentityOpScope op,
        IReadOnlyCollection<Error> errors)
    {
        op.Failure(errors.First().Code);
        return OperationResultFactory.Fail<T>(errors);
    }
}
