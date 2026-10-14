namespace LegacyAuthFinder.Tests;

/// <summary>Test classes in this collection run one after another, never in parallel with the rest.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class SerialCollection
{
    public const string Name = "Serial";
}
