using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace AnomalyDetector.Tests;

public class PatternMatcherTests
{
    private readonly Mock<ILogger> _loggerMock;
    private readonly PatternMatcher _patternMatcher;

    public PatternMatcherTests()
    {
        _loggerMock = new Mock<ILogger>();

        // Predefined malicious patterns
        var maliciousPatterns = new List<Pattern>
        {
            new Pattern("Lateral Movement via RDP", new List<int> { 4624, 4776, 4672, 7045 }),
            new Pattern("Pattern A", new List<int> { 1, 4, 7 }),
            new Pattern("Pattern B", new List<int> { 3, 1, 2, 5 }),
        };
        int timeThresholdInMs = 2000; // 2 seconds

        _patternMatcher = new PatternMatcher(_loggerMock.Object, maliciousPatterns, timeThresholdInMs);
    }

    [Fact]
    public void AddEvent_ShouldTriggerAnomalyDetectedEvent_WhenPatternAMatched()
    {
        // Arrange
        var anomalyTriggered = false;
        string detectedAnomalyName = "";
        List<int> detectedSequence = new();

        _patternMatcher.AnomalyDetected += (anomalyName, eventSequence) =>
        {
            anomalyTriggered = true;
            detectedAnomalyName = anomalyName;
            detectedSequence = new List<int>(eventSequence);
        };

        // Act
        _patternMatcher.AddEvent(1, DateTime.Now);
        _patternMatcher.AddEvent(4, DateTime.Now.AddMilliseconds(10));
        _patternMatcher.AddEvent(7, DateTime.Now.AddMilliseconds(20));

        // Assert
        Assert.True(anomalyTriggered);
        Assert.Equal("Pattern A", detectedAnomalyName);
        Assert.Equal(new List<int> { 1, 4, 7 }, detectedSequence);
    }

    [Fact]
    public void AddEvent_ShouldTriggerAnomalyDetectedEvent_WhenPatternBMatched()
    {
        // Arrange
        var anomalyTriggered = false;
        string detectedAnomalyName = "";
        List<int> detectedSequence = new();

        _patternMatcher.AnomalyDetected += (anomalyName, eventSequence) =>
        {
            anomalyTriggered = true;
            detectedAnomalyName = anomalyName;
            detectedSequence = new List<int>(eventSequence);
        };

        // Act
        _patternMatcher.AddEvent(3, DateTime.Now);
        _patternMatcher.AddEvent(1, DateTime.Now.AddMilliseconds(10));
        _patternMatcher.AddEvent(2, DateTime.Now.AddMilliseconds(20));
        _patternMatcher.AddEvent(5, DateTime.Now.AddMilliseconds(30));

        // Assert
        Assert.True(anomalyTriggered);
        Assert.Equal("Pattern B", detectedAnomalyName);
        Assert.Equal(new List<int> { 3, 1, 2, 5 }, detectedSequence);
    }

    [Fact]
    public void AddEvent_ShouldTriggerAnomalyDetectedEvent_WhenPatternMatched()
    {
        // Arrange
        var anomalyTriggered = false;
        string detectedAnomalyName = "";
        List<int> detectedSequence = new();

        _patternMatcher.AnomalyDetected += (anomalyName, eventSequence) =>
        {
            anomalyTriggered = true;
            detectedAnomalyName = anomalyName;
            detectedSequence = new List<int>(eventSequence);
        };

        // Act
        _patternMatcher.AddEvent(4625, DateTime.Now);
        _patternMatcher.AddEvent(4624, DateTime.Now.AddMilliseconds(10));
        _patternMatcher.AddEvent(7036, DateTime.Now.AddMilliseconds(10));
        _patternMatcher.AddEvent(4776, DateTime.Now.AddMilliseconds(10));
        _patternMatcher.AddEvent(4672, DateTime.Now.AddMilliseconds(10));
        _patternMatcher.AddEvent(7045, DateTime.Now.AddMilliseconds(10));

        // Assert
        Assert.True(anomalyTriggered);
        Assert.Equal("Lateral Movement via RDP", detectedAnomalyName);
        Assert.Equal(new List<int> { 4624, 4776, 4672, 7045 }, detectedSequence);
    }
}
