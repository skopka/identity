using Skopka.Identity.Users;

namespace Skopka.Identity;

public interface IUserOperationPolicy
{
    bool CanMutate(UserFlags flags);
}