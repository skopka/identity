using System.Reflection;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Skopka.Identity.Ef.PostgreSql;

internal sealed class PostgreSqlIdentityMigrationsAssembly(
    IMigrationsIdGenerator idGenerator) : IMigrationsAssembly
{
    private IReadOnlyDictionary<string, TypeInfo>? migrations;
    private ModelSnapshot? modelSnapshot;

    public IReadOnlyDictionary<string, TypeInfo> Migrations
        => migrations ??= Assembly.DefinedTypes
            .Where(type => !type.IsAbstract && type.IsSubclassOf(typeof(Migration)))
            .Select(type => new
            {
                Type = type,
                Id = type.GetCustomAttribute<MigrationAttribute>()?.Id
            })
            .Where(item => item.Id is not null)
            .OrderBy(item => item.Id, StringComparer.Ordinal)
            .ToDictionary(
                item => item.Id!,
                item => item.Type,
                StringComparer.Ordinal);

    public ModelSnapshot? ModelSnapshot
        => modelSnapshot ??= Assembly.DefinedTypes
            .Where(type => !type.IsAbstract && type.IsSubclassOf(typeof(ModelSnapshot)))
            .Select(type => (ModelSnapshot?)Activator.CreateInstance(type.AsType(), nonPublic: true))
            .SingleOrDefault();

    public Assembly Assembly { get; } = typeof(PostgreSqlIdentityMigrationsAssembly).Assembly;

    public string? FindMigrationId(string nameOrId)
        => Migrations.Keys.FirstOrDefault(
            migrationId =>
                string.Equals(migrationId, nameOrId, StringComparison.OrdinalIgnoreCase)
                || string.Equals(
                    idGenerator.GetName(migrationId),
                    nameOrId,
                    StringComparison.OrdinalIgnoreCase));

    public Migration CreateMigration(TypeInfo migrationClass, string activeProvider)
    {
        var migration = (Migration)Activator.CreateInstance(migrationClass.AsType(), nonPublic: true)!;
        migration.ActiveProvider = activeProvider;
        return migration;
    }
}
