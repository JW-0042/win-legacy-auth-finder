using System.Globalization;

namespace LegacyAuthFinder.Core;

/// <summary>
/// How many days of events one log file stands for, and how many days a log of 32 MB, 100 MB, 250 MB or 1 GB would
/// hold on this server at the same load. It tells an admin how busy the server is and how big its log must be to
/// keep enough history. The estimate assumes the load of the period the file covers.
/// </summary>
/// <param name="Rough">The file covers less than a day, so one busy or quiet hour can move the estimate a lot.</param>
public sealed record RetentionEstimate(long Events, double CoveredDays, double EventsPerDay, IReadOnlyList<(long Size, double Days)> At, bool Rough)
{
    public string EventsPerDayText => Retention.Count(EventsPerDay);

    /// <summary>"6 h · 19 h · 2 d · 8 d" for the sizes in <see cref="Retention.Sizes"/>.</summary>
    public string DaysText => (Rough ? "about " : "") + string.Join(" · ", At.Select(a => Retention.DaysText(a.Days)));
}

public static class Retention
{
    /// <summary>The log sizes the estimate is made for.</summary>
    public static IReadOnlyList<long> Sizes { get; } = [32L << 20, 100L << 20, 250L << 20, 1L << 30];

    public static string SizesText => string.Join(" · ", Sizes.Select(Reports.SizeText).Select(s => s.Replace(".0 ", " ", StringComparison.Ordinal)));

    /// <summary>Below this the time range is too short to say anything.</summary>
    private static readonly TimeSpan Shortest = TimeSpan.FromHours(1);
    private const long MinimumEvents = 100;

    /// <summary>
    /// The estimate for one file, or null when it cannot be made: unreadable, almost empty, or covering less than an
    /// hour. Days at a size = days covered × size / bytes used, the bytes of the file without its 4 KB header.
    /// </summary>
    public static RetentionEstimate? For(LogFileInfo file)
    {
        if (file.Error is not null || file.RecordCount < MinimumEvents || file.First is not { } first || file.Last is not { } last) return null;
        var span = last - first;
        var bytes = file.Size - EvtxFileReader.HeaderSize;
        if (span < Shortest || bytes <= 0) return null;
        var days = span.TotalDays;
        return new RetentionEstimate(file.RecordCount, days, file.RecordCount / days, [.. Sizes.Select(s => (s, days * s / bytes))], days < 1);
    }

    /// <summary>"40 min", "9 h", "2.5 d", "38 d", "1.2 y".</summary>
    public static string DaysText(double days) => days switch
    {
        < 1.0 / 24 => $"{Math.Max(1, Math.Round(days * 24 * 60)).ToString("0", CultureInfo.InvariantCulture)} min",
        < 1 => $"{Math.Round(days * 24).ToString("0", CultureInfo.InvariantCulture)} h",
        < 10 => $"{days.ToString("0.#", CultureInfo.InvariantCulture)} d",
        < 730 => $"{days.ToString("0", CultureInfo.InvariantCulture)} d",
        _ => $"{(days / 365).ToString("0.#", CultureInfo.InvariantCulture)} y",
    };

    /// <summary>"950", "13k", "4.2M" events.</summary>
    public static string Count(double n) => n switch
    {
        < 10_000 => n.ToString("N0", CultureInfo.InvariantCulture),
        < 1_000_000 => $"{(n / 1000).ToString("0", CultureInfo.InvariantCulture)}k",
        _ => $"{(n / 1_000_000).ToString("0.#", CultureInfo.InvariantCulture)}M",
    };
}
