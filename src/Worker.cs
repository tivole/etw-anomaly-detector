using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

namespace AnomalyDetector;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private TraceEventSession? _session;
    private readonly PatternMatcher _patternMatcher;

    public Worker(ILogger<Worker> logger)
    {
        _logger = logger;

        var maliciousPatterns = new List<Pattern>
        {
            new Pattern("Lateral Movement via RDP", new List<int> { 4624, 4776, 4672, 7045 }),
            new Pattern("Pattern A", new List<int> { 1, 4, 7 }),
            new Pattern("Pattern B", new List<int> { 3, 1, 2, 5 }),
        };
        int timeThresholdInMs = 2000; // 2 seconds

        _patternMatcher = new PatternMatcher(_logger, maliciousPatterns, timeThresholdInMs);

        // Subscribe to the AnomalyDetected event
        _patternMatcher.AnomalyDetected += OnAnomalyDetected;
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _session = new TraceEventSession("AnomalyDetectionSession");

        _session.EnableProvider("Microsoft-Windows-Security-Auditing");
        _session.EnableProvider("Microsoft-Windows-Sysmon");
        _session.EnableProvider("Microsoft-Windows-PowerShell");
        _session.EnableProvider("Microsoft-Windows-FilteringPlatform");
        _session.EnableProvider("Microsoft-Windows-TaskScheduler");
        _session.EnableProvider("Microsoft-Windows-Windows Defender");

        _session.Source.AllEvents += OnEventRecordWritten;

        stoppingToken.Register(() =>
        {
            _session?.Stop();
            _session?.Dispose();
        });

        Task.Run(() => _session.Source.Process(), stoppingToken);

        return Task.CompletedTask;
    }

    private void OnEventRecordWritten(TraceEvent data)
    {
        int eventId = (int)data.ID;
        DateTime timestamp = data.TimeStamp;

        _logger.LogInformation("Event ID: {EventId}, Timestamp: {Timestamp}", eventId, timestamp);

        // Pass the event to the PatternMatcher for pattern detection
        _patternMatcher.AddEvent(eventId, timestamp);
    }

    private void OnAnomalyDetected(string anomalyName, List<int> eventSequence)
    {
        _logger.LogError("ALERT: {AnomalyName} detected with sequence: {Sequence}", anomalyName, string.Join(", ", eventSequence));
    }

    public override Task StopAsync(CancellationToken stoppingToken)
    {
        _session?.Stop();
        _session?.Dispose();
        return base.StopAsync(stoppingToken);
    }
}
