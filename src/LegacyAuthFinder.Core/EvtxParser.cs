using System.Buffers;
using System.Buffers.Binary;
using System.Globalization;
using System.Security.Principal;
using System.Text;

namespace LegacyAuthFinder.Core;

/// <summary>The file is not a readable .evtx file, or a structure inside it is damaged.</summary>
public sealed class EvtxFormatException(string message) : Exception(message);

/// <summary>A record as seen by the query filters of the built-in parser. Values are decoded only when asked for.</summary>
public interface IRecordView
{
    int EventId { get; }
    string Provider { get; }

    /// <summary>A named EventData value, formatted like <see cref="WindowsEvtxReader"/> does, or "".</summary>
    string Get(string name);

    /// <summary>A named EventData value as a number, read straight from the binary value when it is numeric. Null when missing.</summary>
    uint? Number(string name);
}

/// <summary>A reader that answers several queries in one pass over a file.</summary>
public interface IMultiQueryReader
{
    /// <param name="progress">Called now and then with the share of the file read (0 to 1), or -1 when only alive.</param>
    IEnumerable<(EvtxQuery Query, RawEvent Event)> ReadAll(string path, IReadOnlyList<EvtxQuery> queries, CancellationToken cancellationToken,
        Action<double>? progress = null, ReadStats? stats = null);
}

/// <summary>What one pass over a file found, for the diagnostic log.</summary>
public sealed class ReadStats
{
    public long Bytes;
    public long Chunks;
    public long EmptyChunks;
    public long BadChunks;
    public long ChecksumErrors;
    public long Records;
    public long RecordsPastFree;
    public long BadRecords;
    public long Candidates;
    public long Matches;
    public string? Fallback;
    public string? FirstError;

    internal void Add(ReadStats o)
    {
        Chunks += o.Chunks;
        EmptyChunks += o.EmptyChunks;
        BadChunks += o.BadChunks;
        ChecksumErrors += o.ChecksumErrors;
        Records += o.Records;
        RecordsPastFree += o.RecordsPastFree;
        BadRecords += o.BadRecords;
        Candidates += o.Candidates;
        Matches += o.Matches;
        FirstError ??= o.FirstError;
    }

    public override string ToString() => Fallback is not null
        ? $"read with the Windows event log API ({Fallback})"
        : $"{Bytes / 1048576.0:0} MB, {Chunks:N0} chunks ({EmptyChunks:N0} empty, {BadChunks:N0} damaged, {ChecksumErrors:N0} with a wrong checksum), "
          + $"{Records:N0} records ({BadRecords:N0} unreadable, {RecordsPastFree:N0} recovered from a dirty chunk), {Candidates:N0} with a wanted event ID, "
          + $"{Matches:N0} matched{(FirstError is null ? "" : $", first problem: {FirstError}")}";
}

/// <summary>
/// Reads .evtx files directly instead of through the Windows Event Log service. The format is public: a 4 KB file
/// header, then chunks of 64 KB. Each chunk holds its own string and template tables and a list of records in binary
/// XML. Records are read once for all queries, and a record is only decoded in full when its event ID is wanted.
/// Files that do not start like an .evtx file go to <see cref="Fallback"/>. Damaged chunks and records are skipped
/// and counted, the rest of the file is still read.
/// </summary>
public sealed class EvtxFileReader(IEvtxReader? fallback = null) : IEvtxReader, IMultiQueryReader
{
    internal const int HeaderSize = 4096;
    internal const int ChunkSize = 65536;
    private const int ChunksPerBlock = 64;

    /// <summary>Used for files that are not .evtx files at all. Usually a <see cref="WindowsEvtxReader"/>.</summary>
    public IEvtxReader? Fallback { get; } = fallback;

    public DiagLog? Log { get; set; }

    /// <summary>
    /// Threads that parse the chunks of one file. The chunks of a file are independent, so a big file can be parsed
    /// on several cores while one thread reads the disk sequentially. The scanner sets it from the CPU count.
    /// </summary>
    public int ChunkWorkers { get; set; } = 1;

    public LogFileInfo Inspect(string path)
    {
        try
        {
            return InspectFile(path);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            Log?.Write("INSPECT", $"{Path.GetFileName(path)}: built-in reader cannot read the header ({ex.GetType().Name}: {ex.Message}), using the Windows API");
            if (Fallback is not null) return Fallback.Inspect(path);
            long size = 0;
            try { size = new FileInfo(path).Length; } catch (Exception sizeError) when (sizeError is IOException or UnauthorizedAccessException) { }
            return new LogFileInfo(path, size, "", "", 0, 0, null, null, $"Cannot read this file. It may be damaged or not an event log file. ({ex.Message})");
        }
    }

    public IEnumerable<RawEvent> Read(string path, EvtxQuery query, CancellationToken cancellationToken, Action? alive = null) =>
        ReadAll(path, [query], cancellationToken, alive is null ? null : _ => alive()).Select(x => x.Event);

    public IEnumerable<(EvtxQuery Query, RawEvent Event)> ReadAll(string path, IReadOnlyList<EvtxQuery> queries, CancellationToken cancellationToken,
        Action<double>? progress = null, ReadStats? stats = null)
    {
        stats ??= new ReadStats();
        string? problem = null;
        long firstChunk = 0;
        try
        {
            using var fs = Open(path);
            var header = ReadHeader(fs);
            CheckHeader(header);
            firstChunk = (long)BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(8));
        }
        catch (EvtxFormatException ex)
        {
            problem = ex.Message;
        }

        if (problem is not null)
        {
            if (Fallback is null) throw new EvtxFormatException(problem);
            stats.Fallback = problem;
            Log?.Write("PARSE", $"{Path.GetFileName(path)}: {problem}, reading it with the Windows API");
            foreach (var q in queries)
            {
                foreach (var raw in Fallback.Read(path, q, cancellationToken, () => progress?.Invoke(-1)))
                {
                    yield return (q, raw);
                }
            }
            yield break;
        }

        foreach (var item in Parse(path, firstChunk, queries, cancellationToken, progress, stats)) yield return item;
    }

    private static FileStream Open(string path) =>
        new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1, FileOptions.SequentialScan);

    private static byte[] ReadHeader(FileStream fs)
    {
        var header = new byte[HeaderSize];
        fs.Position = 0;
        if (fs.ReadAtLeast(header, 128, throwOnEndOfStream: false) < 128) throw new EvtxFormatException("The file is too small for an event log file");
        return header;
    }

    private static void CheckHeader(byte[] header)
    {
        if (!header.AsSpan(0, 8).SequenceEqual("ElfFile\0"u8)) throw new EvtxFormatException("The file does not start with the .evtx signature");
        var major = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(38));
        if (major != 3) throw new EvtxFormatException($"Unknown .evtx format version {major}");
    }

    /// <summary>
    /// Chunk ranges in the order Windows reads them: from the oldest chunk named in the file header to the end of the
    /// file, then from the start of the file. A wrapped (circular) log is then read oldest first like with the API.
    /// </summary>
    internal static List<(long Start, int Count)> Blocks(long chunks, long oldest)
    {
        if (oldest < 0 || oldest >= chunks) oldest = 0;
        var blocks = new List<(long, int)>();
        void Range(long from, long to)
        {
            for (var c = from; c < to; c += ChunksPerBlock) blocks.Add((c, (int)Math.Min(ChunksPerBlock, to - c)));
        }
        Range(oldest, chunks);
        Range(0, oldest);
        return blocks;
    }

    private IEnumerable<(EvtxQuery, RawEvent)> Parse(string path, long oldest, IReadOnlyList<EvtxQuery> queries, CancellationToken cancellationToken,
        Action<double>? progress, ReadStats stats)
    {
        var wanted = new bool[65536];
        foreach (var q in queries)
        {
            if (q.EventIds is null) throw new ArgumentException($"Query '{q.Name}' has no event IDs for the built-in reader");
            foreach (var id in q.EventIds) wanted[id & 0xFFFF] = true;
        }

        using var fs = Open(path);
        var chunks = Math.Max(0, (fs.Length - HeaderSize) / ChunkSize);
        var blocks = Blocks(chunks, oldest);
        var workers = Math.Clamp(ChunkWorkers, 1, 16);
        var buffers = new[] { ArrayPool<byte>.Shared.Rent(ChunkSize * ChunksPerBlock), ArrayPool<byte>.Shared.Rent(ChunkSize * ChunksPerBlock) };
        var parsers = Enumerable.Range(0, workers).Select(_ => new ChunkParser()).ToArray();
        var results = new List<(EvtxQuery, RawEvent)>[ChunksPerBlock];
        var chunkStats = new ReadStats[ChunksPerBlock];
        for (var i = 0; i < ChunksPerBlock; i++)
        {
            results[i] = [];
            chunkStats[i] = new ReadStats();
        }

        int ReadBlock(int b, byte[] buffer)
        {
            var (start, count) = blocks[b];
            fs.Position = HeaderSize + start * ChunkSize;
            return fs.ReadAtLeast(buffer.AsSpan(0, count * ChunkSize), count * ChunkSize, throwOnEndOfStream: false);
        }

        Task<int>? next = null;
        long done = 0;
        try
        {
            for (var b = 0; b < blocks.Count; b++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var buffer = buffers[b % 2];
                var read = next is null ? ReadBlock(b, buffer) : next.GetAwaiter().GetResult();
                // Read ahead: the disk fetches the next block while this one is parsed.
                var following = b + 1;
                next = following < blocks.Count ? Task.Run(() => ReadBlock(following, buffers[following % 2]), cancellationToken) : null;
                var count = read / ChunkSize;
                stats.Bytes += read;

                for (var i = 0; i < count; i++)
                {
                    results[i].Clear();
                    chunkStats[i] = new ReadStats();
                }
                if (workers == 1 || count < 2)
                {
                    for (var i = 0; i < count; i++)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        ParseChunk(parsers[0], buffer, i * ChunkSize, queries, wanted, chunkStats[i], results[i]);
                    }
                }
                else
                {
                    var nextChunk = -1;
                    Parallel.For(0, workers, new ParallelOptions { MaxDegreeOfParallelism = workers, CancellationToken = cancellationToken }, w =>
                    {
                        int i;
                        while ((i = Interlocked.Increment(ref nextChunk)) < count)
                        {
                            cancellationToken.ThrowIfCancellationRequested();
                            ParseChunk(parsers[w], buffer, i * ChunkSize, queries, wanted, chunkStats[i], results[i]);
                        }
                    });
                }
                for (var i = 0; i < count; i++)
                {
                    stats.Add(chunkStats[i]);
                    foreach (var item in results[i]) yield return item;
                }
                done += count;
                progress?.Invoke(chunks == 0 ? 1 : Math.Min(1, (double)done / chunks));
                if (count < blocks[b].Count) break;
            }
        }
        finally
        {
            // An abandoned read ahead must finish before its buffer goes back to the pool.
            try { next?.Wait(); } catch (Exception) { /* the read result is not needed anymore */ }
            ArrayPool<byte>.Shared.Return(buffers[0]);
            ArrayPool<byte>.Shared.Return(buffers[1]);
        }
    }

    /// <summary>
    /// One chunk. Every failure inside stays inside: a damaged chunk is counted and the file goes on with the next one.
    /// Records past the free space offset are taken only while they continue the record ID sequence, which recovers
    /// records of a dirty log (copied while Windows was writing) without picking up stale data.
    /// </summary>
    private static void ParseChunk(ChunkParser parser, byte[] buffer, int start, IReadOnlyList<EvtxQuery> queries, bool[] wanted,
        ReadStats stats, List<(EvtxQuery, RawEvent)> found)
    {
        try
        {
            var span = buffer.AsSpan(start, ChunkSize);
            if (!span[..8].SequenceEqual("ElfChnk\0"u8))
            {
                if (span[..8].IndexOfAnyExcept((byte)0) < 0) stats.EmptyChunks++;
                else stats.BadChunks++;
                return;
            }
            stats.Chunks++;
            var free = (int)Math.Min(BinaryPrimitives.ReadUInt32LittleEndian(span[48..]), int.MaxValue);
            if (free < 512 || free > ChunkSize)
            {
                stats.BadChunks++;
                stats.FirstError ??= $"chunk with free space offset {free}";
                return;
            }
            if (Crc32.Compute(span[512..free]) != BinaryPrimitives.ReadUInt32LittleEndian(span[52..])) stats.ChecksumErrors++;

            parser.Begin(buffer, start);
            var pos = 512;
            long previousId = -1;
            while (pos <= ChunkSize - 28)
            {
                var pastFree = pos > free - 28;
                if (BinaryPrimitives.ReadUInt32LittleEndian(span[pos..]) != 0x00002A2A) break;
                var size = BinaryPrimitives.ReadUInt32LittleEndian(span[(pos + 4)..]);
                var limit = pastFree ? ChunkSize : free;
                // Compared as unsigned, so a huge size cannot wrap around.
                if (size < 28 || size > (uint)(limit - pos) || BinaryPrimitives.ReadUInt32LittleEndian(span[(pos + (int)size - 4)..]) != size)
                {
                    if (!pastFree)
                    {
                        stats.BadRecords++;
                        stats.FirstError ??= $"record with size {size}";
                    }
                    break;
                }
                var id = (long)BinaryPrimitives.ReadUInt64LittleEndian(span[(pos + 8)..]);
                if (pastFree)
                {
                    if (previousId < 0 || id != previousId + 1) break;
                    stats.RecordsPastFree++;
                }
                stats.Records++;
                try
                {
                    var written = BinaryPrimitives.ReadInt64LittleEndian(span[(pos + 16)..]);
                    var record = parser.ParseRecord(start + pos + 24, start + pos + (int)size - 4, id, written, wanted);
                    if (record is not null)
                    {
                        stats.Candidates++;
                        foreach (var q in queries)
                        {
                            if (!q.EventIds!.Contains(record.EventId)) continue;
                            if (q.Providers is { } providers && !providers.Contains(record.Provider, StringComparer.OrdinalIgnoreCase)) continue;
                            if (q.Filter is { } filter && !filter(record)) continue;
                            stats.Matches++;
                            found.Add((q, record.Materialize(q)));
                            break;
                        }
                    }
                }
                catch (Exception ex) when (ex is not (OutOfMemoryException or OperationCanceledException))
                {
                    stats.BadRecords++;
                    stats.FirstError ??= $"{ex.GetType().Name}: {ex.Message}";
                }
                previousId = id;
                pos += (int)size;
            }
        }
        catch (Exception ex) when (ex is not (OutOfMemoryException or OperationCanceledException))
        {
            stats.BadChunks++;
            stats.FirstError ??= $"{ex.GetType().Name}: {ex.Message}";
        }
    }

    /// <summary>Record positions of a chunk, with the same bounds checks as the scan.</summary>
    private static List<(int Pos, int Size)> RecordPositions(byte[] buffer)
    {
        var positions = new List<(int, int)>();
        var free = (int)Math.Min(BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(48)), int.MaxValue);
        if (free < 512 || free > ChunkSize) return positions;
        for (var pos = 512; pos <= free - 28;)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(pos)) != 0x00002A2A) break;
            var size = BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(pos + 4));
            if (size < 28 || size > (uint)(free - pos)) break;
            positions.Add((pos, (int)size));
            pos += (int)size;
        }
        return positions;
    }

    /// <summary>Every record of the file with all its values. For the tests that compare the parser with the Windows API.</summary>
    internal static IEnumerable<ParsedRecord> ReadEverything(string path, ReadStats? stats = null)
    {
        stats ??= new ReadStats();
        using var fs = Open(path);
        CheckHeader(ReadHeader(fs));
        var chunks = (fs.Length - HeaderSize) / ChunkSize;
        var buffer = new byte[ChunkSize];
        var parser = new ChunkParser();
        for (long c = 0; c < chunks; c++)
        {
            if (!ReadChunk(fs, c, buffer)) continue;
            stats.Chunks++;
            parser.Begin(buffer, 0);
            var list = new List<ParsedRecord>();
            foreach (var (pos, size) in RecordPositions(buffer))
            {
                stats.Records++;
                var id = (long)BinaryPrimitives.ReadUInt64LittleEndian(buffer.AsSpan(pos + 8));
                try
                {
                    var r = parser.ParseRecord(pos + 24, pos + size - 4, id, BinaryPrimitives.ReadInt64LittleEndian(buffer.AsSpan(pos + 16)), null)!;
                    list.Add(new ParsedRecord(r.RecordId, r.EventId, r.Provider, r.Time, r.ComputerName, r.ChannelName, r.Positional(), r.DataNamed(),
                        r.XmlStyle(), null));
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    stats.BadRecords++;
                    list.Add(new ParsedRecord(id, -1, "", default, "", "", [], [], ([], []), ex.Message));
                }
            }
            foreach (var r in list) yield return r;
        }
    }

    /// <summary>A text dump of how one record was decoded, for debugging differences to the Windows API.</summary>
    internal static string DumpRecord(string path, long recordId)
    {
        using var fs = Open(path);
        CheckHeader(ReadHeader(fs));
        var chunks = (fs.Length - HeaderSize) / ChunkSize;
        var buffer = new byte[ChunkSize];
        var parser = new ChunkParser();
        for (long c = 0; c < chunks; c++)
        {
            if (!ReadChunk(fs, c, buffer)) continue;
            parser.Begin(buffer, 0);
            foreach (var (pos, size) in RecordPositions(buffer))
            {
                var r = parser.ParseRecord(pos + 24, pos + size - 4, 0, 0, null);
                if (r is not null && r.RecordId == recordId) return $"chunk {c}, offset {pos}, size {size}{Environment.NewLine}{r.Dump()}";
            }
        }
        return "not found";
    }

    private LogFileInfo InspectFile(string path)
    {
        using var fs = Open(path);
        var header = ReadHeader(fs);
        CheckHeader(header);
        var length = fs.Length;
        var chunks = (length - HeaderSize) / ChunkSize;
        if (chunks <= 0) return new LogFileInfo(path, length, "(empty)", "", 0, 0, null, null);
        var firstNo = (long)BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(8));
        var lastNo = (long)BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(16));
        if (firstNo < 0 || firstNo >= chunks) firstNo = 0;
        if (lastNo < 0 || lastNo >= chunks) lastNo = chunks - 1;

        var buffer = new byte[ChunkSize];
        // A dirty header (log copied while Windows was writing) can name an older last chunk. Follow the record
        // numbers forward while the next chunk continues them.
        if (ReadChunk(fs, lastNo, buffer))
        {
            var lastNumber = BinaryPrimitives.ReadUInt64LittleEndian(buffer.AsSpan(16));
            for (var step = 1L; step < chunks; step++)
            {
                var candidate = (lastNo + 1) % chunks;
                if (!ReadChunk(fs, candidate, buffer) || BinaryPrimitives.ReadUInt64LittleEndian(buffer.AsSpan(8)) != lastNumber + 1) break;
                lastNo = candidate;
                lastNumber = BinaryPrimitives.ReadUInt64LittleEndian(buffer.AsSpan(16));
            }
        }

        var parser = new ChunkParser();
        RecordFields? first = null, last = null;
        long firstId = 0, lastId = 0, firstNumber = 0, lastNumberFound = 0;
        for (var i = 0L; i < chunks && first is null; i++)
        {
            var no = (firstNo + i) % chunks;
            if (!ReadChunk(fs, no, buffer)) continue;
            (first, firstId) = EdgeRecord(parser, buffer, newest: false);
            firstNumber = (long)BinaryPrimitives.ReadUInt64LittleEndian(buffer.AsSpan(8));
        }
        for (var i = 0L; i < chunks && last is null; i++)
        {
            var no = ((lastNo - i) % chunks + chunks) % chunks;
            if (!ReadChunk(fs, no, buffer)) continue;
            (last, lastId) = EdgeRecord(parser, buffer, newest: true);
            lastNumberFound = (long)BinaryPrimitives.ReadUInt64LittleEndian(buffer.AsSpan(16));
        }
        if (first is null || last is null) return new LogFileInfo(path, length, "(empty)", "", 0, 0, null, null);
        // Record numbers in the chunk headers are contiguous in the file, also for filtered exports where the
        // event IDs have gaps.
        var count = lastNumberFound >= firstNumber && firstNumber > 0 ? lastNumberFound - firstNumber + 1 : Math.Max(0, lastId - firstId + 1);
        return new LogFileInfo(path, length, first.ChannelName, first.ComputerName, count, firstId, first.Time, last.Time,
            FirstRecordId: firstId, LastRecordId: lastId);
    }

    private static bool ReadChunk(FileStream fs, long number, byte[] buffer)
    {
        fs.Position = HeaderSize + number * ChunkSize;
        return fs.ReadAtLeast(buffer, ChunkSize, throwOnEndOfStream: false) == ChunkSize && buffer.AsSpan(0, 8).SequenceEqual("ElfChnk\0"u8);
    }

    /// <summary>The first or the last readable record of a chunk, decoded in full.</summary>
    private static (RecordFields?, long) EdgeRecord(ChunkParser parser, byte[] buffer, bool newest)
    {
        var positions = RecordPositions(buffer);
        if (newest) positions.Reverse();
        foreach (var (pos, size) in positions)
        {
            parser.Begin(buffer, 0);
            try
            {
                var id = (long)BinaryPrimitives.ReadUInt64LittleEndian(buffer.AsSpan(pos + 8));
                var written = BinaryPrimitives.ReadInt64LittleEndian(buffer.AsSpan(pos + 16));
                var record = parser.ParseRecord(pos + 24, pos + size - 4, id, written, null);
                if (record is not null && record.ChannelName.Length > 0) return (record.Detach(), record.RecordId);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                // Try the next record.
            }
        }
        return (null, 0);
    }
}

/// <summary>CRC-32 (IEEE), the checksum of .evtx chunks. Slicing by 8 keeps it fast enough for 4 GB files.</summary>
internal static class Crc32
{
    private static readonly uint[] Table = Build();

    private static uint[] Build()
    {
        var t = new uint[8 * 256];
        for (uint i = 0; i < 256; i++)
        {
            var c = i;
            for (var k = 0; k < 8; k++) c = (c & 1) != 0 ? 0xEDB88320 ^ (c >> 1) : c >> 1;
            t[i] = c;
        }
        for (var i = 0; i < 256; i++)
        {
            for (var s = 1; s < 8; s++) t[s * 256 + i] = (t[(s - 1) * 256 + i] >> 8) ^ t[t[(s - 1) * 256 + i] & 0xFF];
        }
        return t;
    }

    public static uint Compute(ReadOnlySpan<byte> data)
    {
        var crc = 0xFFFFFFFFu;
        var t = Table;
        while (data.Length >= 8)
        {
            var one = BinaryPrimitives.ReadUInt32LittleEndian(data) ^ crc;
            var two = BinaryPrimitives.ReadUInt32LittleEndian(data[4..]);
            crc = t[7 * 256 + (one & 0xFF)] ^ t[6 * 256 + ((one >> 8) & 0xFF)] ^ t[5 * 256 + ((one >> 16) & 0xFF)] ^ t[4 * 256 + (one >> 24)]
                ^ t[3 * 256 + (two & 0xFF)] ^ t[2 * 256 + ((two >> 8) & 0xFF)] ^ t[256 + ((two >> 16) & 0xFF)] ^ t[two >> 24];
            data = data[8..];
        }
        foreach (var b in data) crc = t[(crc ^ b) & 0xFF] ^ (crc >> 8);
        return ~crc;
    }
}

internal sealed record ParsedRecord(long RecordId, int EventId, string Provider, DateTime Time, string Computer, string Channel,
    List<string> Positional, Dictionary<string, string> Named, (Dictionary<string, string> Data, List<string> Values) Xml, string? Error);

internal enum Slot : byte
{
    Provider,
    EventId,
    Time,
    Computer,
    Channel,
    RecordId,
    Data,
    Binary,
    UserLeaf,
    Other,
}

/// <summary>Literal text, or substitution number <see cref="Sub"/> of the template instance.</summary>
internal readonly record struct Piece(string? Literal, int Sub, byte DeclaredType)
{
    public static Piece Text(string text) => new(text, -1, 0);
}

/// <summary>A place in a template that the tool cares about, with the pieces that make up its value.</summary>
internal sealed class Binding(Slot slot, string path, string? name, Piece[]? namePieces, Piece[] pieces)
{
    public Slot Slot { get; } = slot;
    public string Path { get; } = path;

    /// <summary>The Data Name attribute or the UserData element name, when it is plain text.</summary>
    public string? Name { get; } = name;

    public Piece[]? NamePieces { get; } = namePieces;
    public Piece[] Pieces { get; } = pieces;
}

internal sealed class Template(List<Binding> bindings)
{
    public List<Binding> Bindings { get; } = bindings;
    public Binding? EventId { get; } = bindings.FirstOrDefault(b => b.Slot == Slot.EventId);
}

internal struct SubValue
{
    public int Offset;
    public int Size;
    public byte Type;
}

/// <summary>
/// Binary XML of one chunk. Templates and names are cached per chunk, because their offsets are chunk-relative.
/// Every read is bounds-checked against the chunk, so damaged data ends in an <see cref="EvtxFormatException"/>.
/// </summary>
internal sealed class ChunkParser
{
    private const int MaxDepth = 64;
    private const int MaxNesting = 8;

    /// <summary>Nested binary XML values one record may expand. Real events use one or two, crafted files could use millions.</summary>
    internal const int MaxExpansions = 256;

    private byte[] _b = [];
    private int _start;
    private int _end;
    private readonly Dictionary<int, string> _names = [];
    private readonly Dictionary<int, Template?> _topTemplates = [];
    private readonly Dictionary<(int, string), Template?> _nestedTemplates = [];
    private readonly RecordFields _fields;

    public ChunkParser() => _fields = new RecordFields(this);

    /// <summary>Starts a new chunk. Names and templates are chunk-relative, so the caches are emptied every time.</summary>
    public void Begin(byte[] buffer, int start)
    {
        _names.Clear();
        _topTemplates.Clear();
        _nestedTemplates.Clear();
        _b = buffer;
        _start = start;
        _end = start + EvtxFileReader.ChunkSize;
    }

    /// <summary>Parses one record. Returns null when its event ID is not wanted (checked before the full decode).</summary>
    public RecordFields? ParseRecord(int pos, int end, long recordId, long written, bool[]? wanted)
    {
        var f = _fields;
        f.Reset(recordId, written);
        if (end < pos) throw new EvtxFormatException("Record is shorter than its header");
        Fragment(pos, end, "", 0, wanted);
        if (f.Skipped) return null;
        f.ResolveSystem();
        if (wanted is not null && (f.EventId < 0 || !wanted[f.EventId & 0xFFFF])) return null;
        return f;
    }

    private int Rel(int pos) => pos - _start;

    private void Need(int pos, int length)
    {
        if (pos < _start || length < 0 || pos > _end - length) throw new EvtxFormatException("A structure points outside its chunk");
    }

    public byte U8(int p)
    {
        Need(p, 1);
        return _b[p];
    }

    public ushort U16(int p)
    {
        Need(p, 2);
        return BinaryPrimitives.ReadUInt16LittleEndian(_b.AsSpan(p, 2));
    }

    public uint U32(int p)
    {
        Need(p, 4);
        return BinaryPrimitives.ReadUInt32LittleEndian(_b.AsSpan(p, 4));
    }

    public ulong U64(int p)
    {
        Need(p, 8);
        return BinaryPrimitives.ReadUInt64LittleEndian(_b.AsSpan(p, 8));
    }

    private int I32(int p) => (int)U32(p);

    public ReadOnlySpan<byte> Bytes(int p, int length)
    {
        Need(p, length);
        return _b.AsSpan(p, length);
    }

    private string Utf16(int p, int chars) => Encoding.Unicode.GetString(Bytes(p, chars * 2));

    private string Name(int offset)
    {
        if (_names.TryGetValue(offset, out var name)) return name;
        var p = _start + offset;
        name = Utf16(p + 8, U16(p + 6));
        _names[offset] = name;
        return name;
    }

    /// <summary>Name structure: next offset (4), hash (2), length in characters (2), UTF-16 text, terminating zero (2).</summary>
    private int SkipName(int pos) => pos + 10 + U16(pos + 6) * 2;

    /// <summary>A binary XML fragment: optional header, then a template instance or plain elements.</summary>
    private void Fragment(int pos, int end, string context, int nesting, bool[]? wanted)
    {
        if (nesting > MaxNesting) throw new EvtxFormatException("Binary XML is nested too deep");
        while (pos < end)
        {
            var token = U8(pos);
            switch (token)
            {
                case 0x00:
                    return;
                case 0x0F:
                    pos += 4;
                    break;
                case 0x0C:
                    pos = TemplateInstance(pos, context, nesting, wanted);
                    if (_fields.Skipped) return;
                    break;
                case 0x01 or 0x41:
                    var bindings = new List<Binding>();
                    pos = Element(pos, ContextSegments(context), [], bindings, 0);
                    _fields.Add(new Template(bindings), -1, 0);
                    break;
                default:
                    throw new EvtxFormatException($"Unexpected binary XML token 0x{token:x2}");
            }
        }
    }

    /// <summary>
    /// Template instance: token (1), unknown (1), template ID (4), template definition offset (4). When the offset points
    /// right behind it, the definition follows inline (next offset 4, GUID 16, data size 4, data). Then the substitution
    /// array: count (4), count times (size 2, type 1, padding 1), then the values one after another.
    /// </summary>
    private int TemplateInstance(int pos, string context, int nesting, bool[]? wanted)
    {
        var definition = I32(pos + 6);
        pos += 10;
        if (definition == Rel(pos))
        {
            var inline = I32(pos + 20);
            if (inline < 0) throw new EvtxFormatException("Template with a negative size");
            pos += 24 + inline;
        }
        var template = GetTemplate(definition, context);
        var count = I32(pos);
        if (count < 0 || count > 8192) throw new EvtxFormatException($"Template instance with {count} values");
        pos += 4;
        Need(pos, count * 4);
        var first = _fields.ReserveSubs(count);
        var value = pos + count * 4;
        var subs = _fields.Subs;
        for (var i = 0; i < count; i++)
        {
            var size = U16(pos + i * 4);
            subs[first + i] = new SubValue { Offset = value, Size = size, Type = _b[pos + i * 4 + 2] };
            value += size;
        }
        Need(pos + count * 4, value - pos - count * 4);

        // Event ID first: most records are not wanted and need nothing else.
        if (nesting == 0 && wanted is not null && template.EventId is { } eid)
        {
            var id = _fields.Number(eid, first);
            if (id is { } n && (n < 0 || n > 0xFFFF || !wanted[n])) _fields.Skipped = true;
            if (_fields.Skipped) return value;
        }
        _fields.Add(template, first, nesting, count, context);
        return value;
    }

    /// <summary>Called for a substitution of type binary XML: the value is a fragment of its own.</summary>
    internal void Nested(SubValue sub, string context, int nesting)
    {
        if (++_fields.Expansions > MaxExpansions) throw new EvtxFormatException("Too many nested binary XML values in one record");
        Fragment(sub.Offset, sub.Offset + sub.Size, context, nesting + 1, null);
    }

    private Template GetTemplate(int offset, string context)
    {
        var top = context.Length == 0;
        if (top ? _topTemplates.TryGetValue(offset, out var cached) : _nestedTemplates.TryGetValue((offset, context), out cached))
        {
            return cached ?? throw new EvtxFormatException("Damaged template");
        }
        try
        {
            var p = _start + offset;
            var size = I32(p + 20);
            Need(p + 24, size);
            var bindings = new List<Binding>();
            var segments = ContextSegments(context);
            var pos = p + 24;
            var end = p + 24 + size;
            while (pos < end)
            {
                var token = U8(pos);
                if (token == 0x00) break;
                if (token == 0x0F) pos += 4;
                else if (token is 0x01 or 0x41) pos = Element(pos, segments, [], bindings, 0);
                else throw new EvtxFormatException($"Unexpected token 0x{token:x2} in a template");
            }
            var template = new Template(bindings);
            if (top) _topTemplates[offset] = template;
            else _nestedTemplates[(offset, context)] = template;
            return template;
        }
        catch (EvtxFormatException)
        {
            if (top) _topTemplates[offset] = null;
            else _nestedTemplates[(offset, context)] = null;
            throw;
        }
    }

    private static string[] ContextSegments(string context) => context.Length == 0 ? [] : context.Split('/');

    /// <summary>
    /// Element: token (1, 0x41 when it has attributes), dependency ID (2), data size (4), name offset (4), the name when
    /// it is stored inline, and the attribute list size (4) when there are attributes. Then attributes, then 0x02 and the
    /// content up to 0x04, or 0x03 for an empty element.
    /// </summary>
    private int Element(int pos, string[] context, List<string> stack, List<Binding> output, int depth)
    {
        if (depth > MaxDepth) throw new EvtxFormatException("Elements are nested too deep");
        var hasAttributes = (U8(pos) & 0x40) != 0;
        var nameOffset = I32(pos + 7);
        pos += 11;
        if (nameOffset == Rel(pos))
        {
            pos = SkipName(pos);
            if (hasAttributes) pos += 4;
        }
        else if (hasAttributes && nameOffset == Rel(pos + 4))
        {
            pos = SkipName(pos + 4);
        }
        else if (hasAttributes)
        {
            pos += 4;
        }
        var name = Name(nameOffset);
        stack.Add(name);

        List<(string Name, Piece[] Value)>? attributes = null;
        while (U8(pos) is 0x06 or 0x46)
        {
            var attrName = I32(pos + 1);
            pos += 5;
            if (attrName == Rel(pos)) pos = SkipName(pos);
            var value = new List<Piece>(1);
            while (IsValue(U8(pos))) pos = ReadPiece(pos, value);
            (attributes ??= []).Add((Name(attrName), value.ToArray()));
        }

        var content = new List<Piece>(1);
        var children = false;
        var close = U8(pos++);
        if (close == 0x02)
        {
            while (true)
            {
                var token = U8(pos);
                if (token == 0x04)
                {
                    pos++;
                    break;
                }
                if (token is 0x01 or 0x41)
                {
                    children = true;
                    pos = Element(pos, context, stack, output, depth + 1);
                }
                else if (IsValue(token))
                {
                    pos = ReadPiece(pos, content);
                }
                else if (token == 0x0A)
                {
                    var target = I32(pos + 1);
                    pos += 5;
                    if (target == Rel(pos)) pos = SkipName(pos);
                }
                else if (token == 0x0B)
                {
                    pos += 3 + U16(pos + 1) * 2;
                }
                else
                {
                    throw new EvtxFormatException($"Unexpected token 0x{token:x2} in element {name}");
                }
            }
        }
        else if (close != 0x03)
        {
            throw new EvtxFormatException($"Element {name} is not closed");
        }

        Emit(context, stack, name, attributes, content, children, output);
        stack.RemoveAt(stack.Count - 1);
        return pos;
    }

    private static bool IsValue(byte token) => token is 0x05 or 0x45 or 0x0D or 0x0E or 0x07 or 0x47 or 0x08 or 0x48 or 0x09 or 0x49;

    private int ReadPiece(int pos, List<Piece> pieces)
    {
        var token = U8(pos);
        switch (token & 0xBF)
        {
            case 0x05:
                var type = U8(pos + 1);
                if (type != 0x01) throw new EvtxFormatException($"Value text of type 0x{type:x2}");
                var chars = U16(pos + 2);
                pieces.Add(Piece.Text(Utf16(pos + 4, chars)));
                return pos + 4 + chars * 2;
            case 0x0D or 0x0E:
                pieces.Add(new Piece(null, U16(pos + 1), U8(pos + 3)));
                return pos + 4;
            case 0x07:
                var length = U16(pos + 1);
                pieces.Add(Piece.Text(Utf16(pos + 3, length)));
                return pos + 3 + length * 2;
            case 0x08:
                pieces.Add(Piece.Text(((char)U16(pos + 1)).ToString()));
                return pos + 3;
            default:
                var entity = I32(pos + 1);
                var next = pos + 5;
                if (entity == Rel(next)) next = SkipName(next);
                pieces.Add(Piece.Text(Name(entity) switch
                {
                    "amp" => "&",
                    "lt" => "<",
                    "gt" => ">",
                    "quot" => "\"",
                    "apos" => "'",
                    var other => $"&{other};",
                }));
                return next;
        }
    }

    private static Piece[]? Attr(List<(string Name, Piece[] Value)>? attributes, string name)
    {
        if (attributes is null) return null;
        foreach (var (n, v) in attributes)
        {
            if (n == name) return v;
        }
        return null;
    }

    /// <summary>Records what an element means, from its own name, its parent and whether it sits under UserData.</summary>
    private static void Emit(string[] context, List<string> stack, string name, List<(string Name, Piece[] Value)>? attributes,
        List<Piece> content, bool children, List<Binding> output)
    {
        var parent = stack.Count >= 2 ? stack[^2] : context.Length > 0 ? context[^1] : "";
        var path = string.Join('/', context.Concat(stack));
        if (parent == "System")
        {
            switch (name)
            {
                case "Provider" when Attr(attributes, "Name") is { } provider:
                    output.Add(new Binding(Slot.Provider, path, null, null, provider));
                    return;
                case "EventID":
                    output.Add(new Binding(Slot.EventId, path, null, null, [.. content]));
                    return;
                case "TimeCreated" when Attr(attributes, "SystemTime") is { } time:
                    output.Add(new Binding(Slot.Time, path, null, null, time));
                    return;
                case "Computer":
                    output.Add(new Binding(Slot.Computer, path, null, null, [.. content]));
                    return;
                case "Channel":
                    output.Add(new Binding(Slot.Channel, path, null, null, [.. content]));
                    return;
                case "EventRecordID":
                    output.Add(new Binding(Slot.RecordId, path, null, null, [.. content]));
                    return;
            }
        }
        if (parent == "EventData" && name == "Data")
        {
            var namePieces = Attr(attributes, "Name");
            var plain = namePieces is { Length: 1 } && namePieces[0].Sub < 0 ? namePieces[0].Literal : namePieces is { Length: 0 } ? "" : null;
            output.Add(new Binding(Slot.Data, path, plain, plain is null ? namePieces : null, [.. content]));
            return;
        }
        if (parent == "EventData" && name == "Binary")
        {
            output.Add(new Binding(Slot.Binary, path, null, null, [.. content]));
            return;
        }
        var underUserData = context.Contains("UserData") || stack.Take(stack.Count - 1).Contains("UserData");
        if (underUserData && !children && name != "UserData")
        {
            output.Add(new Binding(Slot.UserLeaf, path, name, null, [.. content]));
            return;
        }
        if (content.Any(p => p.Sub >= 0)) output.Add(new Binding(Slot.Other, path, null, null, [.. content]));
    }
}

/// <summary>The decoded parts of one record. Reused for every record of a pass, so nothing here may be kept.</summary>
internal sealed class RecordFields(ChunkParser parser) : IRecordView
{
    /// <summary>Substitution values one record may hold, nested instances included.</summary>
    internal const int MaxSubs = 65536;

    private readonly List<(Binding Binding, int First)> _entries = [];

    // Sources of the positional values: a binding of the outer template, or (binding null) every value of a nested
    // template instance. Windows returns all values of a nested instance, also those its template never uses.
    private readonly List<(Binding? Binding, int First, int Count)> _positional = [];
    internal SubValue[] Subs = new SubValue[256];
    private int _subCount;

    // System fields are found by ResolveSystem but decoded only when asked for. Most candidates are filtered out first.
    private (Binding? B, int First) _computerAt, _channelAt, _recordIdAt, _timeAt;
    private string? _provider, _computer, _channel;
    private long? _recordId;
    private DateTime? _time;
    private long _headerId;

    public bool Skipped;
    public int Expansions;
    public long Written;
    public int EventId { get; private set; } = -1;
    public string Provider => _provider ??= Text(Slot.Provider);
    public string ComputerName => _computer ??= _computerAt.B is { } b ? Join(b.Pieces, _computerAt.First, "") : "";
    public string ChannelName => _channel ??= _channelAt.B is { } b ? Join(b.Pieces, _channelAt.First, "") : "";

    /// <summary>Exported logs renumber the record headers from 1, the event itself keeps its original ID in System/EventRecordID.</summary>
    public long RecordId => _recordId ??= _recordIdAt.B is { } b && Long(b, _recordIdAt.First) is > 0 and var original ? original : _headerId;

    public DateTime Time => _time ??= _timeAt.B is { } b && TimeOf(b, _timeAt.First) is { } t ? t : DateTime.FromFileTime(Written);

    public void Reset(long recordId, long written)
    {
        _entries.Clear();
        _positional.Clear();
        _subCount = 0;
        _provider = _computer = _channel = null;
        _recordId = null;
        _time = null;
        _computerAt = _channelAt = _recordIdAt = _timeAt = default;
        Skipped = false;
        Expansions = 0;
        _headerId = recordId;
        Written = written;
        EventId = -1;
    }

    public int ReserveSubs(int count)
    {
        var first = _subCount;
        _subCount += count;
        if (_subCount > MaxSubs) throw new EvtxFormatException("Too many substitution values in one record");
        if (_subCount > Subs.Length) Array.Resize(ref Subs, Math.Max(_subCount, Subs.Length * 2));
        return first;
    }

    /// <summary>Adds the bindings of a template. Values of type binary XML are expanded in place, so the order stays.</summary>
    public void Add(Template template, int first, int nesting, int count = 0, string context = "")
    {
        // A nested instance under UserData: Windows returns all its values. Under EventData (classic events) it goes
        // by the Data elements like the outer template.
        var wholeInstance = nesting > 0 && first >= 0 && context.Contains("UserData", StringComparison.Ordinal);
        if (wholeInstance) _positional.Add((null, first, count));
        foreach (var b in template.Bindings)
        {
            var nested = false;
            if (first >= 0)
            {
                foreach (var p in b.Pieces)
                {
                    if (p.Sub < 0 || !TryGet(first, p.Sub, out var sub) || sub.Type != 0x21) continue;
                    parser.Nested(sub, b.Path, nesting);
                    nested = true;
                }
            }
            if (nested || b.Slot == Slot.Other) continue;
            _entries.Add((b, first));
            if (!wholeInstance && b.Slot is Slot.Data or Slot.UserLeaf or Slot.Binary) _positional.Add((b, first, 0));
        }
    }

    private bool TryGet(int first, int index, out SubValue sub)
    {
        sub = default;
        if (first < 0) return false;
        var i = first + index;
        if (index < 0 || i >= _subCount) return false;
        sub = Subs[i];
        return true;
    }

    /// <summary>Finds the system fields. Only the event ID is decoded here, the rest when it is used.</summary>
    public void ResolveSystem()
    {
        foreach (var (b, first) in _entries)
        {
            switch (b.Slot)
            {
                case Slot.EventId when EventId < 0:
                    EventId = Number(b, first) is { } n and >= 0 and <= 0xFFFF ? n : -1;
                    break;
                case Slot.Computer:
                    _computerAt = (b, first);
                    break;
                case Slot.Channel:
                    _channelAt = (b, first);
                    break;
                case Slot.Time:
                    _timeAt = (b, first);
                    break;
                case Slot.RecordId:
                    _recordIdAt = (b, first);
                    break;
            }
        }
    }

    /// <summary>A number from a single substitution or literal, used for the event ID.</summary>
    public int? Number(Binding b, int first)
    {
        if (b.Pieces.Length != 1) return int.TryParse(Join(b.Pieces, first, ""), out var joined) ? joined : null;
        var p = b.Pieces[0];
        if (p.Sub < 0) return int.TryParse(p.Literal, out var literal) ? literal : null;
        if (!TryGet(first, p.Sub, out var sub) || sub.Size == 0) return null;
        return sub.Type switch
        {
            0x04 => (int?)parser.U8(sub.Offset),
            0x06 => (int?)parser.U16(sub.Offset),
            0x05 => (int?)(short)parser.U16(sub.Offset),
            0x07 or 0x08 or 0x14 => (int?)(int)parser.U32(sub.Offset),
            _ => int.TryParse(WindowsEvtxReader.Format("", Value(sub)), out var parsed) ? parsed : null,
        };
    }

    private long? Long(Binding b, int first)
    {
        if (b.Pieces is [{ Sub: >= 0 } p] && TryGet(first, p.Sub, out var sub) && sub.Size == 8 && sub.Type is 0x09 or 0x0A or 0x15)
        {
            return (long)parser.U64(sub.Offset);
        }
        return long.TryParse(Join(b.Pieces, first, ""), out var parsed) ? parsed : null;
    }

    public uint? Number(string name)
    {
        foreach (var (b, first) in _entries)
        {
            if (b.Slot != Slot.Data || NameOf(b, first) != name) continue;
            if (b.Pieces is [{ Sub: >= 0 } p] && TryGet(first, p.Sub, out var sub) && sub.Size > 0)
            {
                switch (sub.Type)
                {
                    case 0x04: return parser.U8(sub.Offset);
                    case 0x06: return parser.U16(sub.Offset);
                    case 0x07 or 0x08 or 0x14 when sub.Size >= 4: return parser.U32(sub.Offset);
                    case 0x09 or 0x0A or 0x15 when sub.Size >= 8:
                        var wide = parser.U64(sub.Offset);
                        return wide <= uint.MaxValue ? (uint)wide : null;
                }
            }
            return Classifier.ParseEtype(Join(b.Pieces, first, name));
        }
        return null;
    }

    private DateTime? TimeOf(Binding b, int first)
    {
        if (b.Pieces is [{ Sub: >= 0 } p] && TryGet(first, p.Sub, out var sub) && Value(sub) is DateTime t) return t;
        return null;
    }

    private string Text(Slot slot)
    {
        foreach (var (b, first) in _entries)
        {
            if (b.Slot == slot) return Join(b.Pieces, first, "");
        }
        return "";
    }

    private string Join(Piece[] pieces, int first, string field)
    {
        if (pieces.Length == 0) return "";
        if (pieces.Length == 1) return PieceText(pieces[0], first, field);
        var sb = new StringBuilder();
        foreach (var p in pieces) sb.Append(PieceText(p, first, field));
        return sb.ToString();
    }

    private string PieceText(Piece p, int first, string field) =>
        p.Sub < 0 ? p.Literal ?? "" : TryGet(first, p.Sub, out var sub) ? WindowsEvtxReader.Format(field, Value(sub)) : "";

    private string NameOf(Binding b, int first) => b.Name ?? (b.NamePieces is { } np ? Join(np, first, "") : "");

    /// <summary>A named EventData value, exactly what the property selector Event/EventData/Data[@Name='x'] returns.</summary>
    public string Get(string name)
    {
        foreach (var (b, first) in _entries)
        {
            if (b.Slot != Slot.Data) continue;
            if (NameOf(b, first) != name) continue;
            return Join(b.Pieces, first, name);
        }
        return "";
    }

    /// <summary>
    /// The user data values in document order, like EventRecord.Properties: one entry per substitution in EventData
    /// or UserData. Text written into the template itself is not a property.
    /// </summary>
    public List<string> Positional()
    {
        var values = new List<string>();
        foreach (var (b, first, count) in _positional)
        {
            if (b is null)
            {
                for (var i = 0; i < count; i++)
                {
                    if (TryGet(first, i, out var sub) && sub.Type != 0x00 && sub.Type != 0x21) values.Add(WindowsEvtxReader.Format("", Value(sub)));
                }
                continue;
            }
            foreach (var p in b.Pieces)
            {
                if (p.Sub < 0) continue;
                if (!TryGet(first, p.Sub, out var sub))
                {
                    values.Add("");
                    continue;
                }
                // Windows leaves out null values, and returns the elements of an array in an unnamed Data element
                // (classic events keep all their insertion strings in one string array) as properties of their own.
                if (sub.Type == 0x00) continue;
                var value = Value(sub);
                if ((sub.Type & 0x80) != 0 && b.Slot == Slot.Data && NameOf(b, first).Length == 0)
                {
                    if (value is Array array and not byte[])
                    {
                        foreach (var item in array) values.Add(WindowsEvtxReader.Format("", item));
                    }
                    else if (value is not Array)
                    {
                        // A damaged array came back as hex text: keep it in its place so later positions do not shift.
                        values.Add(WindowsEvtxReader.Format("", value));
                    }
                    continue;
                }
                values.Add(WindowsEvtxReader.Format("", value));
            }
        }
        return values;
    }

    /// <summary>
    /// EventData and UserData the way the Windows reader's XML fallback sees them (<see cref="WindowsEvtxReader.EventDataFromXml"/>):
    /// one entry per Data element, "ParamN" for unnamed ones, a string array as one element per string, UserData leaves by element name, values rendered like the event XML (hex with 0x, GUIDs in braces, ISO times).
    /// </summary>
    public (Dictionary<string, string> Data, List<string> Values) XmlStyle()
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var values = new List<string>();
        var i = 0;
        foreach (var (b, first) in _entries)
        {
            if (b.Slot is not (Slot.Data or Slot.UserLeaf)) continue;
            var name = NameOf(b, first);
            // The XML writes a string array as one element per string, named ones repeat the name.
            if (b.Pieces.Count(p => p.Sub >= 0) == 1
                && b.Pieces.All(p => p.Sub >= 0 || string.IsNullOrWhiteSpace(p.Literal))
                && TryGet(first, b.Pieces.First(p => p.Sub >= 0).Sub, out var arraySub)
                && (arraySub.Type & 0x80) != 0 && Value(arraySub) is string[] strings)
            {
                foreach (var text in strings)
                {
                    if (b.Slot == Slot.Data) i++;
                    var item = XmlBlank(XmlLines(text));
                    data[name.Length > 0 ? name : $"Param{i}"] = item;
                    values.Add(item);
                }
                continue;
            }
            // An unnamed Data element with only a null value is not rendered at all.
            if (b.Slot == Slot.Data && name.Length == 0 && b.Pieces.Length > 0
                && b.Pieces.All(p => p.Sub >= 0 && (!TryGet(first, p.Sub, out var s) || s.Type == 0x00)))
            {
                continue;
            }
            if (b.Slot == Slot.Data) i++;
            var value = XmlBlank(XmlJoin(b.Pieces, first));
            data[name.Length > 0 ? name : $"Param{i}"] = value;
            values.Add(value);
        }
        return (data, values);
    }

    private string XmlJoin(Piece[] pieces, int first)
    {
        var sb = new StringBuilder();
        foreach (var p in pieces)
        {
            if (p.Sub < 0) sb.Append(XmlLines(p.Literal ?? ""));
            else if (TryGet(first, p.Sub, out var sub)) sb.Append(XmlText(sub));
        }
        return sb.ToString();
    }

    /// <summary>Reading XML turns CR LF and a lone CR into LF.</summary>
    private static string XmlLines(string text) => text.Contains('\r') ? text.Replace("\r\n", "\n").Replace('\r', '\n') : text;

    /// <summary>Parsing the XML drops a text node that is only whitespace.</summary>
    private static string XmlBlank(string text) => text.Length > 0 && text.All(c => c is ' ' or '\t' or '\n') ? "" : text;

    /// <summary>A value as the event XML renders it.</summary>
    private string XmlText(SubValue sub)
    {
        // Unlike its property values, the XML of an event shows an Int16 as the full number.
        if (sub.Type == 0x05 && sub.Size >= 2) return ((short)parser.U16(sub.Offset)).ToString(CultureInfo.InvariantCulture);
        var value = Value(sub);
        return value switch
        {
            null => "",
            string s => XmlLines(s),
            bool flag => flag ? "true" : "false",
            Guid g => "{" + g.ToString("D") + "}",
            DateTime t => t.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture),
            byte[] bytes => Convert.ToHexString(bytes),
            SecurityIdentifier sid => sid.Value,
            int i when sub.Type == 0x14 => $"0x{i:x}",
            ulong u when sub.Type is 0x15 or 0x10 => $"0x{u:x}",
            string[] items => XmlLines(string.Concat(items.Select(x => "\n" + x))),
            IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
            _ => value.ToString() ?? "",
        };
    }

    /// <summary>What the parser saw in the current record, for debugging.</summary>
    public string Dump()
    {
        var sb = new StringBuilder();
        foreach (var (b, first) in _entries)
        {
            sb.Append($"{b.Slot} {b.Path} name={NameOf(b, first)}:");
            foreach (var p in b.Pieces)
            {
                if (p.Sub < 0) sb.Append($" '{p.Literal}'");
                else if (TryGet(first, p.Sub, out var sub)) sb.Append($" #{p.Sub}(declared 0x{p.DeclaredType:x2}, type 0x{sub.Type:x2}, {sub.Size} bytes)");
                else sb.Append($" #{p.Sub}(missing)");
            }
            sb.AppendLine();
        }
        sb.AppendLine($"substitutions in this record: {_subCount}");
        for (var i = 0; i < _subCount; i++) sb.AppendLine($"  sub {i}: type 0x{Subs[i].Type:x2}, {Subs[i].Size} bytes");
        return sb.ToString();
    }

    /// <summary>Named EventData values only, the way a property selector Event/EventData/Data[@Name='x'] sees them.</summary>
    public Dictionary<string, string> DataNamed()
    {
        var data = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (b, first) in _entries)
        {
            if (b.Slot != Slot.Data) continue;
            var name = NameOf(b, first);
            if (name.Length > 0) data.TryAdd(name, Join(b.Pieces, first, name));
        }
        return data;
    }

    public RawEvent Materialize(EvtxQuery q)
    {
        Dictionary<string, string> data;
        IReadOnlyList<string>? values = null;
        if (q.Positional)
        {
            data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            values = Positional();
        }
        else if (q.Fields is null)
        {
            // The Windows reader renders these events as XML, so render the same way.
            (data, var xmlValues) = XmlStyle();
            values = xmlValues;
        }
        else
        {
            data = new Dictionary<string, string>(q.Fields.Count, StringComparer.OrdinalIgnoreCase);
            foreach (var field in q.Fields)
            {
                var v = Get(field);
                if (v.Length > 0) data[field] = v;
            }
        }
        return new RawEvent(EventId, Provider, Time, ComputerName, RecordId, data, values);
    }

    /// <summary>A copy of the system fields that survives the next record.</summary>
    public RecordFields Detach()
    {
        var copy = new RecordFields(parser) { Written = Written };
        copy.EventId = EventId;
        copy._provider = Provider;
        copy._computer = ComputerName;
        copy._channel = ChannelName;
        copy._recordId = RecordId;
        copy._time = Time;
        return copy;
    }

    /// <summary>
    /// Decodes a substitution value into the same .NET types the Windows reader returns, so formatting is identical.
    /// A value that does not decode (an impossible date, a broken SID) comes back as hex text instead of failing the record.
    /// </summary>
    public object? Value(SubValue sub)
    {
        try
        {
            return Decode(sub);
        }
        catch (Exception ex) when (ex is ArgumentException or OverflowException or FormatException)
        {
            return Convert.ToHexString(parser.Bytes(sub.Offset, sub.Size));
        }
    }

    private object? Decode(SubValue sub)
    {
        var p = sub.Offset;
        var n = sub.Size;
        if (n == 0 && sub.Type != 0x01)
        {
            // An empty array is still an array for the Windows reader. Only the null type is null.
            return sub.Type switch
            {
                0x81 or 0x82 => System.Array.Empty<string>(),
                0x83 => System.Array.Empty<sbyte>(),
                0x84 => System.Array.Empty<byte>(),
                0x85 => System.Array.Empty<short>(),
                0x86 => System.Array.Empty<ushort>(),
                0x87 or 0x94 => System.Array.Empty<int>(),
                0x88 => System.Array.Empty<uint>(),
                0x89 => System.Array.Empty<long>(),
                0x8A or 0x90 or 0x95 => System.Array.Empty<ulong>(),
                0x8B => System.Array.Empty<float>(),
                0x8C => System.Array.Empty<double>(),
                0x8D => System.Array.Empty<bool>(),
                0x8F => System.Array.Empty<Guid>(),
                0x91 or 0x92 => System.Array.Empty<DateTime>(),
                0x93 => System.Array.Empty<SecurityIdentifier>(),
                _ => null,
            };
        }
        switch (sub.Type)
        {
            case 0x00: return null;
            case 0x01: return TrimNul(Encoding.Unicode.GetString(parser.Bytes(p, n & ~1)));
            case 0x02: return TrimNul(Encoding.Latin1.GetString(parser.Bytes(p, n)));
            case 0x03: return (sbyte)parser.U8(p);
            case 0x04: return parser.U8(p);
            case 0x05: return parser.U8(p); // the Windows reader returns the low byte of an Int16 (EvtVarTypeInt16)
            case 0x06: return parser.U16(p);
            case 0x07: return (int)parser.U32(p);
            case 0x08: return parser.U32(p);
            case 0x09: return (long)parser.U64(p);
            case 0x0A: return parser.U64(p);
            case 0x0B: return BitConverter.Int32BitsToSingle((int)parser.U32(p));
            case 0x0C: return BitConverter.Int64BitsToDouble((long)parser.U64(p));
            case 0x0D: return parser.U32(p) != 0;
            case 0x0E: return parser.Bytes(p, n).ToArray();
            case 0x0F: return new Guid(parser.Bytes(p, 16));
            case 0x10: return n == 8 ? parser.U64(p) : (ulong)parser.U32(p);
            case 0x11: return DateTime.FromFileTime((long)parser.U64(p));
            case 0x12: return SystemTime(p);
            case 0x13: return new SecurityIdentifier(parser.Bytes(p, n).ToArray(), 0);
            case 0x14: return (int)parser.U32(p);
            case 0x15: return parser.U64(p);
            case 0x81:
                // Every element ends with a zero, so only the very last one is cut off. Empty elements stay.
                var text = Encoding.Unicode.GetString(parser.Bytes(p, n & ~1));
                if (text.EndsWith('\0')) text = text[..^1];
                return text.Split('\0');
            case 0x82:
                var ansi = Encoding.Latin1.GetString(parser.Bytes(p, n));
                if (ansi.EndsWith('\0')) ansi = ansi[..^1];
                return ansi.Split('\0');
            case 0x83: return ReadArray(p, n, 1, i => (sbyte)parser.U8(i));
            case 0x84: return parser.Bytes(p, n).ToArray();
            case 0x85: return ReadArray(p, n, 2, i => (short)parser.U16(i));
            case 0x86: return ReadArray(p, n, 2, i => parser.U16(i));
            case 0x87: return ReadArray(p, n, 4, i => (int)parser.U32(i));
            case 0x88: return ReadArray(p, n, 4, i => parser.U32(i));
            case 0x89: return ReadArray(p, n, 8, i => (long)parser.U64(i));
            case 0x8A: return ReadArray(p, n, 8, i => parser.U64(i));
            case 0x8B: return ReadArray(p, n, 4, i => BitConverter.Int32BitsToSingle((int)parser.U32(i)));
            case 0x8C: return ReadArray(p, n, 8, i => BitConverter.Int64BitsToDouble((long)parser.U64(i)));
            case 0x8D: return ReadArray(p, n, 4, i => parser.U32(i) != 0);
            case 0x8F: return ReadArray(p, n, 16, i => new Guid(parser.Bytes(i, 16)));
            case 0x90: return ReadArray(p, n, 8, i => parser.U64(i));
            case 0x91: return ReadArray(p, n, 8, i => DateTime.FromFileTime((long)parser.U64(i)));
            case 0x92: return ReadArray(p, n, 16, SystemTime);
            case 0x93: return Sids(p, n);
            case 0x94: return ReadArray(p, n, 4, i => (int)parser.U32(i));
            case 0x95: return ReadArray(p, n, 8, i => parser.U64(i));
            default: return parser.Bytes(p, n).ToArray();
        }
    }

    private static T[] ReadArray<T>(int p, int n, int size, Func<int, T> read)
    {
        var result = new T[n / size];
        for (var i = 0; i < result.Length; i++) result[i] = read(p + i * size);
        return result;
    }

    /// <summary>SIDs one after another: each is 8 bytes plus 4 per sub-authority (count at byte 1).</summary>
    private SecurityIdentifier[] Sids(int p, int n)
    {
        var list = new List<SecurityIdentifier>();
        var end = p + n;
        while (p + 8 <= end)
        {
            var length = 8 + parser.U8(p + 1) * 4;
            if (p + length > end) break;
            list.Add(new SecurityIdentifier(parser.Bytes(p, length).ToArray(), 0));
            p += length;
        }
        return [.. list];
    }

    private DateTime SystemTime(int p)
    {
        int W(int i) => parser.U16(p + i * 2);
        return new DateTime(W(0), W(1), W(3), W(4), W(5), W(6), W(7));
    }

    private static string TrimNul(string s)
    {
        var end = s.IndexOf('\0');
        return end >= 0 ? s[..end] : s;
    }
}
