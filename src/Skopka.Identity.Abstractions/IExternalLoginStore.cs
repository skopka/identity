namespace Skopka.Identity;

public sealed record ExternalLoginKey(string Provider, string Subject);

public interface IExternalLoginStore
{
    Task<bool> ExistsAsync(Guid userId, CancellationToken ct);
    // этап 2:
    // Task<OperationResult> LinkAsync(Guid userId, ExternalLoginKey key, CancellationToken ct);
    // Task<Guid?> FindUserIdAsync(ExternalLoginKey key, CancellationToken ct);
}
