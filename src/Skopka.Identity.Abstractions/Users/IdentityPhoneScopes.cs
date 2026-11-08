namespace Skopka.Identity.Users;

/// <summary>
/// Phone scopes let one phone number belong to several accounts that sign in at different
/// places, for example a personal account on the main site and a staff account on a staff
/// site. A phone number is unique within its scope; user names and emails stay unique
/// across all scopes.
/// </summary>
/// <remarks>
/// A scope is a trusted, server-selected identifier, never a value taken from a request.
/// It is compared ordinally. Hosts that do not use scopes leave every account in
/// <see cref="Default"/>, which keeps global phone uniqueness. Lookups that do not name a
/// scope search <see cref="Default"/> only.
/// </remarks>
public static class IdentityPhoneScopes
{
    /// <summary>The scope of accounts whose host does not name one.</summary>
    public const string Default = "";

    /// <summary>Maximum length of a phone scope.</summary>
    public const int MaximumLength = 128;
}
