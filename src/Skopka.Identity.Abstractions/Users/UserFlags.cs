namespace Skopka.Identity.Users;

[Flags]
public enum UserFlags
{
    None = 0,
    System = 1,
    Protected = 2,
    ServiceAccount = 4,
}
