using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Skopka.Identity.Metrics;

internal sealed class IdentityMetrics
{
    public Histogram<double> DurationMs { get; }
    public Counter<long> Attempts { get; }
    public Counter<long> Failures { get; }

    public IdentityMetrics(IMeterFactory? meterFactory = null)
    {
        var meter = meterFactory?.Create("Skopka.Identity", "1.0.0")
                    ?? new Meter("Skopka.Identity", "1.0.0");

        DurationMs = meter.CreateHistogram<double>("identity.user.op.duration_ms", unit: "ms");
        Attempts   = meter.CreateCounter<long>("identity.user.op.attempts");
        Failures   = meter.CreateCounter<long>("identity.user.op.failures");
    }

    public OpScope Begin(string op)
        => new(this, op, Stopwatch.GetTimestamp());

    public readonly struct OpScope : IDisposable
    {
        private readonly IdentityMetrics _m;
        private readonly string _op;
        private readonly long _start;

        public OpScope(IdentityMetrics m, string op, long start)
        {
            _m = m;
            _op = op;
            _start = start;
            _m.Attempts.Add(1, new KeyValuePair<string, object?>("op", _op));
        }

        public void Success()
        {
            Record("success", errorCode: null);
        }

        public void Failure(string errorCode)
        {
            _m.Failures.Add(1,
                new("op", _op),
                new("error_code", errorCode));
            Record("failure", errorCode);
        }

        private void Record(string result, string? errorCode)
        {
            var elapsed = Stopwatch.GetElapsedTime(_start).TotalMilliseconds;
            if (errorCode is null)
            {
                _m.DurationMs.Record(elapsed, new("op", _op), new("result", result));
            }
            else
            {
                _m.DurationMs.Record(elapsed,
                    new("op", _op),
                    new("result", result),
                    new("error_code", errorCode));
            }
        }

        public void Dispose() { /* no-op */ }
    }
}