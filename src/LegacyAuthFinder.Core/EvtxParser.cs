using System.Buffers;
using System.Buffers.Binary;
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

    /// <summary>A named EventData or UserData value, formatted like <see cref="WindowsEvtxReader"/> does, or "".</summary>
    string Get(string name);
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
    public long Records;
    public long BadRecords;
    public long Candidates;
    public long Matches;
    public string? Fallback;
    public string? FirstError;

    public override string ToString() => Fallback is not null
        ? $"read with the Windows event log API ({Fallback})"
        : $"{Bytes / 1048576.0:0} MB, {Chunks:N0} chunks ({EmptyChunks:N0} empty, {BadChunks:N0} damaged), {Records:N0} records "
          + $"({BadRecords:N0} unreadable), {Candidates:N0} with a wanted event ID, {Matches:N0} matched{(FirstError is null ? "" : $", first problem: {FirstError}")}";
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

    public LogFileInfo Inspect(string path)
    {
        try
        {
            return InspectFile(path);
        }
        catch (Exception ex) when (ex is EvtxFormatException or IOException or UnauthorizedAccessException or ArgumentException)
        {
            Log?.Write("INSPECT", $"{Path.GetFileName(path)}: built-in reader cannot read the header ({ex.Message}), using the Windows API");
            if (Fallback is not null) return Fallback.Inspect(path);
            long size = 0;
            try { size = new FileInfo(path).Length; } catch (IOException) { }
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
        try
        {
            using var fs = Open(path);
            CheckHeader(ReadHeader(fs));
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

        foreach (var item in Parse(path, queries, cancellationToken, progress, stats)) yield return item;
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

    private IEnumerable<(EvtxQuery, RawEvent)> Parse(string path, IReadOnlyList<EvtxQuery> queries, CancellationToken cancellationToken,
        Action<double>? progress, ReadStats stats)
    {
        var wanted = new bool[65536];
        foreach (var q in queries)
        {
            if (q.EventIds is null) throw new ArgumentException($"Query '{q.Name}' has no event IDs for the built-in reader");
            foreach (var id in q.EventIds) wanted[id & 0xFFFF] = true;
        }

        using var fs = Open(path);
        var length = fs.Length;
        var chunks = Math.Max(0, (length - HeaderSize) / ChunkSize);
        var block = ArrayPool<byte>.Shared.Rent(ChunkSize * ChunksPerBlock);
        var parser = new ChunkParser();
        var found = new List<(EvtxQuery, RawEvent)>();
        try
        {
            fs.Position = HeaderSize;
            for (long c = 0; c < chunks; c += ChunksPerBlock)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var count = (int)Math.Min(ChunksPerBlock, chunks - c);
                var read = fs.ReadAtLeast(block.AsSpan(0, count * ChunkSize), count * ChunkSize, throwOnEndOfStream: false);
                count = read / ChunkSize;
                stats.Bytes += read;
                for (var i = 0; i < count; i++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    found.Clear();
                    ParseChunk(parser, block, i * ChunkSize, queries, wanted, stats, found);
                    foreach (var item in found) yield return item;
                }
                progress?.Invoke(chunks == 0 ? 1 : Math.Min(1, (double)(c + count) / chunks));
                if (count < Math.Min(ChunksPerBlock, chunks - c)) break;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(block);
        }
    }

    private static void ParseChunk(ChunkParser parser, byte[] buffer, int start, IReadOnlyList<EvtxQuery> queries, bool[] wanted,
        ReadStats stats, List<(EvtxQuery, RawEvent)> found)
    {
        var span = buffer.AsSpan(start, ChunkSize);
        if (!span[..8].SequenceEqual("ElfChnk\0"u8))
        {
            if (span[..8].IndexOfAnyExcept((byte)0) < 0) stats.EmptyChunks++;
            else stats.BadChunks++;
            return;
        }
        stats.Chunks++;
        var free = (int)BinaryPrimitives.ReadUInt32LittleEndian(span[48..]);
        if (free < 512 || free > ChunkSize)
        {
            stats.BadChunks++;
            stats.FirstError ??= $"chunk with free space offset {free}";
            return;
        }
        parser.Begin(buffer, start);
        var pos = 512;
        while (pos + 28 <= free)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(span[pos..]) != 0x00002A2A) break;
            var size = (int)BinaryPrimitives.ReadUInt32LittleEndian(span[(pos + 4)..]);
            if (size < 28 || pos + size > ChunkSize)
            {
                stats.BadRecords++;
                stats.FirstError ??= $"record with size {size}";
                break;
            }
            stats.Records++;
            try
            {
                var id = (long)BinaryPrimitives.ReadUInt64LittleEndian(span[(pos + 8)..]);
                var written = BinaryPrimitives.ReadInt64LittleEndian(span[(pos + 16)..]);
                var record = parser.ParseRecord(start + pos + 24, start + pos + size - 4, id, written, wanted);
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
            catch (Exception ex) when (ex is EvtxFormatException or ArgumentException or IndexOutOfRangeException or OverflowException or DecoderFallbackException)
            {
                stats.BadRecords++;
                stats.FirstError ??= ex.Message;
            }
            pos += size;
        }
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
            var free = (int)BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(48));
            parser.Begin(buffer, 0);
            var list = new List<ParsedRecord>();
            for (var pos = 512; pos + 28 <= Math.Min(free, ChunkSize);)
            {
                if (BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(pos)) != 0x00002A2A) break;
                var size = (int)BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(pos + 4));
                if (size < 28 || pos + size > ChunkSize) break;
                stats.Records++;
                var id = (long)BinaryPrimitives.ReadUInt64LittleEndian(buffer.AsSpan(pos + 8));
                try
                {
                    var r = parser.ParseRecord(pos + 24, pos + size - 4, id, BinaryPrimitives.ReadInt64LittleEndian(buffer.AsSpan(pos + 16)), null)!;
                    list.Add(new ParsedRecord(r.RecordId, r.EventId, r.Provider, r.Time, r.ComputerName, r.ChannelName, r.Positional(), r.DataNamed(), null));
                }
                catch (Exception ex) when (ex is EvtxFormatException or ArgumentException or IndexOutOfRangeException or OverflowException)
                {
                    stats.BadRecords++;
                    list.Add(new ParsedRecord(id, -1, "", default, "", "", [], [], ex.Message));
                }
                pos += size;
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
            var free = (int)BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(48));
            parser.Begin(buffer, 0);
            for (var pos = 512; pos + 28 <= Math.Min(free, ChunkSize);)
            {
                if (BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(pos)) != 0x00002A2A) break;
                var size = (int)BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(pos + 4));
                if (size < 28) break;
                var r = parser.ParseRecord(pos + 24, pos + size - 4, 0, 0, null);
                if (r is not null && r.RecordId == recordId) return $"chunk {c}, offset {pos}, size {size}{Environment.NewLine}{r.Dump()}";
                pos += size;
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
        var parser = new ChunkParser();
        RecordFields? first = null, last = null;
        long firstId = 0, lastId = 0;
        // The header names the oldest and the newest chunk. A copied live log can be dirty, so look further when they are empty.
        for (var i = 0L; i < chunks && first is null; i++)
        {
            var no = (firstNo + i) % chunks;
            if (ReadChunk(fs, no, buffer)) (first, firstId) = EdgeRecord(parser, buffer, newest: false);
        }
        for (var i = 0L; i < chunks && last is null; i++)
        {
            var no = ((lastNo - i) % chunks + chunks) % chunks;
            if (ReadChunk(fs, no, buffer)) (last, lastId) = EdgeRecord(parser, buffer, newest: true);
        }
        if (first is null || last is null) return new LogFileInfo(path, length, "(empty)", "", 0, 0, null, null);
        var count = lastId >= firstId ? lastId - firstId + 1 : 0;
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
        var free = (int)BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(48));
        if (free < 512 || free > ChunkSize) return (null, 0);
        var positions = new List<(int Pos, int Size)>();
        for (var pos = 512; pos + 28 <= free;)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(pos)) != 0x00002A2A) break;
            var size = (int)BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(pos + 4));
            if (size < 28 || pos + size > ChunkSize) break;
            positions.Add((pos, size));
            pos += size;
        }
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
            catch (Exception ex) when (ex is EvtxFormatException or ArgumentException or IndexOutOfRangeException or OverflowException or DecoderFallbackException)
            {
                // Try the next record.
            }
        }
        return (null, 0);
    }
}

internal sealed record ParsedRecord(long RecordId, int EventId, string Provider, DateTime Time, string Computer, string Channel,
    List<string> Positional, Dictionary<string, string> Named, string? Error);

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

    private byte[] _b = [];
    private int _start;
    private int _end;
    private readonly Dictionary<int, string> _names = [];
    private readonly Dictionary<(int, string), Template?> _templates = [];
    private readonly RecordFields _fields;

    public ChunkParser() => _fields = new RecordFields(this);

    /// <summary>Starts a new chunk. Names and templates are chunk-relative, so the caches are emptied every time.</summary>
    public void Begin(byte[] buffer, int start)
    {
        _names.Clear();
        _templates.Clear();
        _b = buffer;
        _start = start;
        _end = start + EvtxFileReader.ChunkSize;
    }

    public byte[] Buffer => _b;

    /// <summary>Parses one record. Returns null when its event ID is not wanted (checked before the full decode).</summary>
    public RecordFields? ParseRecord(int pos, int end, long recordId, long written, bool[]? wanted)
    {
        var f = _fields;
        f.Reset(recordId, written);
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
        if (definition == Rel(pos)) pos += 24 + I32(pos + 20);
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
    internal void Nested(SubValue sub, string context, int nesting) => Fragment(sub.Offset, sub.Offset + sub.Size, context, nesting + 1, null);

    private Template GetTemplate(int offset, string context)
    {
        if (_templates.TryGetValue((offset, context), out var cached)) return cached ?? throw new EvtxFormatException("Damaged template");
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
            _templates[(offset, context)] = template;
            return template;
        }
        catch (EvtxFormatException)
        {
            _templates[(offset, context)] = null;
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
    private readonly List<(Binding Binding, int First)> _entries = [];

    // Sources of the positional values: a binding of the outer template, or (binding null) every value of a nested
    // template instance. Windows returns all values of a nested instance, also those its template never uses.
    private readonly List<(Binding? Binding, int First, int Count)> _positional = [];
    internal SubValue[] Subs = new SubValue[256];
    private int _subCount;
    private string? _provider;

    public bool Skipped;
    public long RecordId;
    public long Written;
    public int EventId { get; private set; } = -1;
    public string Provider => _provider ??= Text(Slot.Provider);
    public string ComputerName { get; private set; } = "";
    public string ChannelName { get; private set; } = "";
    public DateTime Time { get; private set; }

    public void Reset(long recordId, long written)
    {
        _entries.Clear();
        _positional.Clear();
        _subCount = 0;
        _provider = null;
        Skipped = false;
        RecordId = recordId;
        Written = written;
        EventId = -1;
        ComputerName = "";
        ChannelName = "";
    }

    public int ReserveSubs(int count)
    {
        var first = _subCount;
        _subCount += count;
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
                    ComputerName = Join(b.Pieces, first, "");
                    break;
                case Slot.Channel:
                    ChannelName = Join(b.Pieces, first, "");
                    break;
                case Slot.Time:
                    Time = TimeOf(b, first);
                    break;
                case Slot.RecordId:
                    // Exported logs renumber the record headers from 1, the event itself keeps its original ID.
                    if (long.TryParse(Join(b.Pieces, first, ""), out var original) && original > 0) RecordId = original;
                    break;
            }
        }
        if (Time == default) Time = DateTime.FromFileTime(Written);
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

    private DateTime TimeOf(Binding b, int first)
    {
        if (b.Pieces is [{ Sub: >= 0 } p] && TryGet(first, p.Sub, out var sub) && Value(sub) is DateTime t) return t;
        return default;
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

    public string Get(string name)
    {
        foreach (var (b, first) in _entries)
        {
            if (b.Slot is not (Slot.Data or Slot.UserLeaf)) continue;
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
                    continue;
                }
                values.Add(WindowsEvtxReader.Format("", value));
            }
        }
        return values;
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

    /// <summary>All named values, with "ParamN" for unnamed Data elements, like the XML fallback of the Windows reader.</summary>
    public Dictionary<string, string> AllNamed()
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var i = 0;
        foreach (var (b, first) in _entries)
        {
            if (b.Slot is not (Slot.Data or Slot.UserLeaf)) continue;
            if (b.Slot == Slot.Data) i++;
            var name = NameOf(b, first);
            if (name.Length == 0) name = $"Param{i}";
            data[name] = Join(b.Pieces, first, name);
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
            data = AllNamed();
            values = Positional();
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
        var copy = new RecordFields(parser) { RecordId = RecordId, Written = Written };
        copy.EventId = EventId;
        copy._provider = Provider;
        copy.ComputerName = ComputerName;
        copy.ChannelName = ChannelName;
        copy.Time = Time;
        return copy;
    }

    /// <summary>
    /// Decodes a substitution value into the same .NET types the Windows reader returns, so formatting is identical.
    /// </summary>
    public object? Value(SubValue sub)
    {
        var p = sub.Offset;
        var n = sub.Size;
        if (n == 0 && sub.Type != 0x01)
        {
            // An empty array is still an array for the Windows reader. Only the null type is null.
            return sub.Type switch
            {
                0x81 => System.Array.Empty<string>(),
                0x86 => System.Array.Empty<ushort>(),
                0x88 => System.Array.Empty<uint>(),
                0x8A or 0x95 => System.Array.Empty<ulong>(),
                0x94 => System.Array.Empty<int>(),
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
            case 0x86: return ReadArray(p, n, 2, i => parser.U16(i));
            case 0x88: return ReadArray(p, n, 4, i => parser.U32(i));
            case 0x8A: return ReadArray(p, n, 8, i => parser.U64(i));
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
