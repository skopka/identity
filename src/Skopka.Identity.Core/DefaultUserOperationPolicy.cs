using Skopka.Identity.Users;

namespace Skopka.Identity;

public sealed class DefaultUserOperationPolicy : IUserOperationPolicy
{
    public bool CanMutate(UserFlags flags)
        => (flags & (UserFlags.System | UserFlags.Protected)) == 0;
}
