using Skopka.Identity;
using Skopka.Identity.Ef;
using Skopka.Identity.Ef.PostgreSql;
using Skopka.Identity.Ef.Sqlite;
using Skopka.Identity.Verification;

Type[] packageSurfaces =
[
    typeof(IIdentityNormalizer),
    typeof(DefaultIdentityNormalizer),
    typeof(IdentityDbContext<>),
    typeof(PostgreSqlIdentityDbContext<>),
    typeof(SqliteIdentityDbContext<>),
    typeof(HmacOneTimeCodeOptions),
    typeof(IdentityBuilder<>),
];

var assemblies = packageSurfaces
    .Select(type => type.Assembly.GetName())
    .Select(name => $"{name.Name} {name.Version}")
    .ToArray();

if (assemblies.Length != 7
    || assemblies.Any(string.IsNullOrWhiteSpace))
{
    throw new InvalidOperationException(
        "The complete Skopka.Identity package surface could not be loaded.");
}

Console.WriteLine(string.Join(Environment.NewLine, assemblies));
