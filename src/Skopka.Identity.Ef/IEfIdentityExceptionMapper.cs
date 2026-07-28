using System.Diagnostics.CodeAnalysis;
using Microsoft.EntityFrameworkCore;
using Skopka.Abstraction.OperationResult;

namespace Skopka.Identity.Ef;

public interface IEfIdentityExceptionMapper
{
    bool TryMap(DbUpdateException exception, [NotNullWhen(true)] out Error? error);
}
