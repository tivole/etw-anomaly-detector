namespace AnomalyDetector;

public class Pattern(string name, List<int> eventIds)
{
    public string Name { get; } = name;
    public List<int> EventIds { get; } = eventIds;
}
