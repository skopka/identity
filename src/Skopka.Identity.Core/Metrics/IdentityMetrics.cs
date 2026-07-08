using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Skopka.Identity.Metrics;

public sealed class IdentityMetrics : IIdentityMetrics, IDisposable
{
    private const string MeterName = "Skopka.Identity";
    private const string MeterVersion = "1.0.0";
    private const string UncompletedScopeErrorCode = "identity.metrics.uncompleted_scope";

    private readonly Meter _meter;
    private readonly bool _ownsMeter;
    private bool _disposed;

    public Histogram<double> DurationMs { get; }
    public Counter<long> Attempts { get; }
    public Counter<long> Failures { get; }

    public IdentityMetrics(IMeterFactory? meterFactory = null)
    {
        _meter = meterFactory?.Create(MeterName, MeterVersion) ?? new Meter(MeterName, MeterVersion);
        _ownsMeter = meterFactory is null;

        DurationMs = _meter.CreateHistogram<double>("identity.user.op.duration_ms", unit: "ms");
        Attempts = _meter.CreateCounter<long>("identity.user.op.attempts");
        Failures = _meter.CreateCounter<long>("identity.user.op.failures");
    }

    public IIdentityOpScope Begin(string operation)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (string.IsNullOrWhiteSpace(operation))
            throw new ArgumentException("Operation name is required.", nameof(operation));

        Attempts.Add(1, new KeyValuePair<string, object?>("op", operation));
        return new OpScope(this, operation, Stopwatch.GetTimestamp());
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;

        if (_ownsMeter)
            _meter.Dispose();
    }

    private sealed class OpScope : IIdentityOpScope
    {
        private readonly IdentityMetrics _metrics;
        private readonly string _operation;
        private readonly long _start;
        private int _completed;

        public OpScope(IdentityMetrics metrics, string operation, long start)
        {
            _metrics = metrics;
            _operation = operation;
            _start = start;
        }

        public void Success() => Complete("success", errorCode: null);

        public void Failure(string errorCode)
        {
            if (string.IsNullOrWhiteSpace(errorCode))
                errorCode = "identity.error.unknown";

            if (!TryComplete())
                return;

            _metrics.Failures.Add(1,
                new("op", _operation),
                new("error_code", errorCode));

            Record("failure", errorCode);
        }

        public void Dispose()
        {
            if (!TryComplete())
                return;

            _metrics.Failures.Add(1,
                new("op", _operation),
                new("error_code", UncompletedScopeErrorCode));

            Record("failure", UncompletedScopeErrorCode);
        }

        private void Complete(string result, string? errorCode)
        {
            if (!TryComplete())
                return;

            Record(result, errorCode);
        }

        private bool TryComplete()
            => Interlocked.Exchange(ref _completed, 1) == 0;

        private void Record(string result, string? errorCode)
        {
            var elapsed = Stopwatch.GetElapsedTime(_start).TotalMilliseconds;

            if (errorCode is null)
            {
                _metrics.DurationMs.Record(elapsed, new("op", _operation), new("result", result));
            }
            else
            {
                _metrics.DurationMs.Record(elapsed,
                    new("op", _operation),
                    new("result", result),
                    new("error_code", errorCode));
            }
        }
    }
}

