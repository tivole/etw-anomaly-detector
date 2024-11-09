namespace AnomalyDetector;

public class PatternMatcher
{
    public delegate void AnomalyDetectedHandler(string anomalyName, List<int> eventSequence);
    public event AnomalyDetectedHandler? AnomalyDetected;

    private readonly ILogger _logger;
    private readonly List<Pattern> _maliciousPatterns;
    private readonly int _timeThresholdInMs;
    private readonly Queue<(int EventId, DateTime Timestamp)> _eventStream = new();

    public PatternMatcher(ILogger logger, List<Pattern> maliciousPatterns, int timeThresholdInMs)
    {
        _logger = logger;
        _maliciousPatterns = maliciousPatterns;
        _timeThresholdInMs = timeThresholdInMs;
    }

    public void AddEvent(int eventId, DateTime timestamp)
    {
        _eventStream.Enqueue((eventId, timestamp));

        // Remove events outside the time window
        while (_eventStream.Count > 0 && (DateTime.Now - _eventStream.Peek().Timestamp).TotalMilliseconds > _timeThresholdInMs)
        {
            _eventStream.Dequeue();
        }

        // Check for any malicious patterns in the current stream
        foreach (var pattern in _maliciousPatterns)
        {
            if (IsPatternInStream(pattern.EventIds))
            {
                _logger.LogWarning("Anomaly Detected: {AnomalyName} with sequence: {Pattern}", pattern.Name, string.Join(", ", pattern.EventIds));
                
                // Trigger the AnomalyDetected event
                AnomalyDetected?.Invoke(pattern.Name, pattern.EventIds);
                break;
            }
        }
    }

    private bool IsPatternInStream(List<int> pattern)
    {
        int patternIndex = 0;
        DateTime? firstTimestamp = null;

        foreach (var (eventId, timestamp) in _eventStream)
        {
            if (eventId == pattern[patternIndex])
            {
                if (firstTimestamp == null)
                {
                    firstTimestamp = timestamp;
                }
                else if ((timestamp - firstTimestamp.Value).TotalMilliseconds > _timeThresholdInMs)
                {
                    return false;
                }

                patternIndex++;

                if (patternIndex == pattern.Count)
                {
                    return true;
                }
            }
        }
        return false;
    }
}
