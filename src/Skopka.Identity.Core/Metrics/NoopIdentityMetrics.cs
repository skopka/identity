namespace Skopka.Identity.Metrics;

public sealed class NoopIdentityMetrics : IIdentityMetrics
{
    private static readonly IIdentityOpScope Scope = new NoopScope();

    public IIdentityOpScope Begin(string operation) => Scope;

    private sealed class NoopScope : IIdentityOpScope
    {
        public void Success() { }
        public void Failure(string errorCode) { }
        public void Dispose() { }
    }
}
