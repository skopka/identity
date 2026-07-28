using Skopka.Abstraction.OperationResult;
using Skopka.Identity.Users;
using Skopka.Identity.Users.Commands;

namespace Skopka.Identity;

public interface IIdentityUserService<TProfile>
{
    Task<OperationResult<IdentityUser<TProfile>>> CreateAsync(CreateUserCommand<TProfile> cmd, CancellationToken ct);

    Task<OperationResult<IdentityUser<TProfile>>> ConfirmEmailAsync(ConfirmEmailCommand cmd, CancellationToken ct);
    Task<OperationResult<IdentityUser<TProfile>>> ConfirmPhoneAsync(ConfirmPhoneCommand cmd, CancellationToken ct);

    Task<OperationResult<IdentityUser<TProfile>>> ChangeUserNameAsync(ChangeUserNameCommand cmd, CancellationToken ct);
    Task<OperationResult<IdentityUser<TProfile>>> ChangeEmailAsync(ChangeEmailCommand cmd, CancellationToken ct);
    Task<OperationResult<IdentityUser<TProfile>>> ChangePhoneAsync(ChangePhoneCommand cmd, CancellationToken ct);

    Task<OperationResult<IdentityUser<TProfile>>> PatchProfileAsync<TPatch>(PatchProfileCommand<TPatch> cmd, CancellationToken ct);

    Task<OperationResult<IdentityUser<TProfile>>> BlockAsync(BlockUserCommand cmd, CancellationToken ct);
    Task<OperationResult<IdentityUser<TProfile>>> UnblockAsync(UnblockUserCommand cmd, CancellationToken ct);

    Task<OperationResult> DeleteAsync(DeleteUserCommand cmd, CancellationToken ct);
    Task<OperationResult<IdentityUser<TProfile>>> RestoreAsync(RestoreUserCommand cmd, CancellationToken ct);
} 