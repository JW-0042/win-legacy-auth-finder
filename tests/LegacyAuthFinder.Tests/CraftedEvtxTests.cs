using System.Buffers.Binary;
using System.Diagnostics;
using System.Text;
using LegacyAuthFinder.Core;
using Xunit.Abstractions;

namespace LegacyAuthFinder.Tests;

/// <summary>
/// Writes small .evtx files byte by byte: file header, one or more 64 KB chunks, records in binary XML with inline
/// templates. Used for damaged and malicious input that real logs do not contain.
/// </summary>
internal sealed class EvtxWriter
{
    /// <summary>A Data element. A null name writes an unnamed Data element, like classic events have.</summary>
    public sealed record Field(string? Name, byte Type, byte[] Value);

    public sealed record Record(long Id, int EventId, string Provider, IReadOnlyList<Field> Data, string Channel = "Security", string Computer = "DC01.lab.local");

    private readonly byte[] _c = new byte[EvtxFileReader.ChunkSize];
    private int _p;

    public List<int> RecordOffsets { get; } = [];
    public int Free { get; private set; }

    public static byte[] Utf16(string s) => Encoding.Unicode.GetBytes(s);

    public static byte[] U32(uint v)
    {
        var b = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(b, v);
        return b;
    }

    private void B(byte v) => _c[_p++] = v;

    private void W16(int v)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(_c.AsSpan(_p), (ushort)v);
        _p += 2;
    }

    private void W32(uint v)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(_c.AsSpan(_p), v);
        _p += 4;
    }

    private void W64(ulong v)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(_c.AsSpan(_p), v);
        _p += 8;
    }

    private void Bytes(byte[] b)
    {
        b.CopyTo(_c, _p);
        _p += b.Length;
    }

    /// <summary>Name structure, always written inline: next offset, hash, length, UTF-16, terminating zero.</summary>
    private void Name(string name)
    {
        W32(0);
        W16(0);
        W16(name.Length);
        Bytes(Utf16(name));
        W16(0);
    }

    private void Start(string name, bool attributes)
    {
        var start = _p;
        B((byte)(attributes ? 0x41 : 0x01));
        W16(0xFFFF);
        W32(0);
        W32((uint)(start + 11));
        Name(name);
        if (attributes) W32(0);
    }

    private void Attribute(string name, Action value)
    {
        var start = _p;
        B(0x06);
        W32((uint)(start + 5));
        Name(name);
        value();
    }

    private void Text(string text)
    {
        B(0x05);
        B(0x01);
        W16(text.Length);
        Bytes(Utf16(text));
    }

    private void Sub(int id, byte type)
    {
        B(0x0E);
        W16(id);
        B(type);
    }

    private void Leaf(string name, int sub, byte type)
    {
        Start(name, false);
        B(0x02);
        Sub(sub, type);
        B(0x04);
    }

    /// <summary>Template instance with the definition inline, then the substitution values written by <paramref name="values"/>.</summary>
    private void Instance(Action templateBody, IReadOnlyList<(byte Type, Action Write)> values)
    {
        B(0x0C);
        B(0x01);
        W32(1);
        W32((uint)(_p + 4));
        W32(0);
        Bytes(new byte[16]);
        var sizeAt = _p;
        W32(0);
        var dataStart = _p;
        B(0x0F); B(0x01); B(0x01); B(0x00);
        templateBody();
        B(0x00);
        BinaryPrimitives.WriteUInt32LittleEndian(_c.AsSpan(sizeAt), (uint)(_p - dataStart));
        W32((uint)values.Count);
        var descriptors = _p;
        _p += values.Count * 4;
        for (var i = 0; i < values.Count; i++)
        {
            var start = _p;
            values[i].Write();
            BinaryPrimitives.WriteUInt16LittleEndian(_c.AsSpan(descriptors + i * 4), (ushort)(_p - start));
            _c[descriptors + i * 4 + 2] = values[i].Type;
        }
    }

    private void RecordShell(long id, Action binXml)
    {
        var start = _p;
        RecordOffsets.Add(start);
        W32(0x00002A2A);
        W32(0);
        W64((ulong)id);
        W64((ulong)new DateTime(2026, 10, 1, 8, 0, 0, DateTimeKind.Utc).ToFileTimeUtc());
        B(0x0F); B(0x01); B(0x01); B(0x00);
        binXml();
        B(0x00);
        var size = (uint)(_p - start + 4);
        W32(size);
        BinaryPrimitives.WriteUInt32LittleEndian(_c.AsSpan(start + 4), size);
    }

    /// <summary>A normal record: System with event ID, time, record ID, provider, channel and computer, then named Data.</summary>
    public EvtxWriter Add(Record r)
    {
        if (_p == 0) _p = 512;
        RecordShell(r.Id, () => Instance(() =>
            {
                Start("Event", false);
                B(0x02);
                Start("System", false);
                B(0x02);
                Start("Provider", true);
                Attribute("Name", () => Sub(3, 0x01));
                B(0x03);
                Leaf("EventID", 0, 0x06);
                Start("TimeCreated", true);
                Attribute("SystemTime", () => Sub(1, 0x11));
                B(0x03);
                Leaf("EventRecordID", 2, 0x0A);
                Leaf("Channel", 4, 0x01);
                Leaf("Computer", 5, 0x01);
                B(0x04);
                Start("EventData", false);
                B(0x02);
                for (var i = 0; i < r.Data.Count; i++)
                {
                    var name = r.Data[i].Name;
                    if (name is null)
                    {
                        Start("Data", false);
                    }
                    else
                    {
                        Start("Data", true);
                        Attribute("Name", () => Text(name));
                    }
                    B(0x02);
                    Sub(6 + i, r.Data[i].Type);
                    B(0x04);
                }
                B(0x04);
                B(0x04);
            },
            [
                (0x06, () => W16(r.EventId)),
                (0x11, () => W64((ulong)new DateTime(2026, 10, 1, 8, 0, 0, DateTimeKind.Utc).ToFileTimeUtc())),
                (0x0A, () => W64((ulong)r.Id)),
                (0x01, () => Bytes(Utf16(r.Provider))),
                (0x01, () => Bytes(Utf16(r.Channel))),
                (0x01, () => Bytes(Utf16(r.Computer))),
                .. r.Data.Select(f => (f.Type, (Action)(() => Bytes(f.Value)))),
            ]));
        return this;
    }

    /// <summary>
    /// A record whose EventData holds <paramref name="pieces"/> references to one nested binary XML value, and that
    /// value again holds <paramref name="pieces"/> references to a string. Without a limit this expands pieces² times.
    /// </summary>
    public EvtxWriter AddNestedBomb(long id, int pieces)
    {
        if (_p == 0) _p = 512;
        RecordShell(id, () => Instance(() =>
            {
                Start("Event", false);
                B(0x02);
                Start("System", false);
                B(0x02);
                Leaf("EventID", 0, 0x06);
                B(0x04);
                Start("EventData", false);
                B(0x02);
                for (var i = 0; i < pieces; i++) Sub(1, 0x21);
                B(0x04);
                B(0x04);
            },
            [
                (0x06, () => W16(4769)),
                (0x21, () =>
                {
                    B(0x0F); B(0x01); B(0x01); B(0x00);
                    Instance(() =>
                    {
                        Start("Data", false);
                        B(0x02);
                        for (var i = 0; i < pieces; i++) Sub(0, 0x01);
                        B(0x04);
                    }, [(0x01, () => Bytes(Utf16("x")))]);
                    B(0x00);
                }),
            ]));
        return this;
    }

    /// <summary>Finishes the chunk: header fields, free space offset and the records checksum.</summary>
    /// <param name="firstId">The first record ID in the chunk header (offset 24). Windows writes it, older tests leave it 0.</param>
    public byte[] Chunk(long firstNumber = 1, int? free = null, long firstId = 0)
    {
        Free = free ?? _p;
        "ElfChnk\0"u8.CopyTo(_c);
        BinaryPrimitives.WriteUInt64LittleEndian(_c.AsSpan(8), (ulong)firstNumber);
        BinaryPrimitives.WriteUInt64LittleEndian(_c.AsSpan(16), (ulong)(firstNumber + RecordOffsets.Count - 1));
        if (firstId > 0)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(_c.AsSpan(24), (ulong)firstId);
            BinaryPrimitives.WriteUInt64LittleEndian(_c.AsSpan(32), (ulong)(firstId + RecordOffsets.Count - 1));
        }
        BinaryPrimitives.WriteUInt32LittleEndian(_c.AsSpan(40), 128);
        BinaryPrimitives.WriteUInt32LittleEndian(_c.AsSpan(44), (uint)(RecordOffsets.Count > 0 ? RecordOffsets[^1] : 0));
        BinaryPrimitives.WriteUInt32LittleEndian(_c.AsSpan(48), (uint)Free);
        BinaryPrimitives.WriteUInt32LittleEndian(_c.AsSpan(52), Crc32.Compute(_c.AsSpan(512, Free - 512)));
        return _c;
    }

    public static byte[] File(long oldestChunk, params byte[][] chunks) => File(oldestChunk, (oldestChunk + chunks.Length - 1) % chunks.Length, chunks);

    /// <summary>A file whose header names any oldest and newest chunk, also stale ones like a log copied while Windows wrote it.</summary>
    public static byte[] File(long oldestChunk, long newestChunk, params byte[][] chunks)
    {
        var file = new byte[EvtxFileReader.HeaderSize + chunks.Length * EvtxFileReader.ChunkSize];
        "ElfFile\0"u8.CopyTo(file);
        BinaryPrimitives.WriteUInt64LittleEndian(file.AsSpan(8), (ulong)oldestChunk);
        BinaryPrimitives.WriteUInt64LittleEndian(file.AsSpan(16), (ulong)newestChunk);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(32), 128);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(36), 2);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(38), 3);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(40), 4096);
        for (var i = 0; i < chunks.Length; i++) chunks[i].CopyTo(file, EvtxFileReader.HeaderSize + i * EvtxFileReader.ChunkSize);
        return file;
    }
}

public sealed class CraftedEvtxTests(ITestOutputHelper output) : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("laf-crafted-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string Save(string name, byte[] bytes)
    {
        var path = Path.Combine(_dir, name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private static EvtxWriter.Record Rc4(long id, string user = "bob", params EvtxWriter.Field[] extra) => new(id, 4769, Providers.SecurityAuditing,
    [
        new("TargetUserName", 0x01, EvtxWriter.Utf16(user)),
        new("ServiceName", 0x01, EvtxWriter.Utf16("svc-sql")),
        new("TicketEncryptionType", 0x14, EvtxWriter.U32(0x17)),
        new("IpAddress", 0x01, EvtxWriter.Utf16("::ffff:10.0.0.9")),
        .. extra,
    ]);

    private static List<(EvtxQuery Query, RawEvent Event)> Read(string path, ReadStats stats, params EvtxQuery[] queries) =>
        new EvtxFileReader().ReadAll(path, queries.Length > 0 ? queries : [Queries.Kerberos], CancellationToken.None, null, stats).ToList();

    [Fact]
    public void A_crafted_file_is_read_like_a_real_one()
    {
        var path = Save("ok.evtx", EvtxWriter.File(0, new EvtxWriter().Add(Rc4(100)).Add(Rc4(101, "alice")).Chunk()));
        var stats = new ReadStats();
        var found = Read(path, stats);
        output.WriteLine(stats.ToString());
        Assert.Equal(2, found.Count);
        var e = found[0].Event;
        Assert.Equal((4769, "bob", "0x17", 100L), (e.EventId, e["TargetUserName"], e["TicketEncryptionType"], e.RecordId));
        Assert.Equal("DC01.lab.local", e.Computer);
        Assert.Equal(0, stats.ChecksumErrors);
        var info = new EvtxFileReader().Inspect(path);
        Assert.Equal(("Security", 100L, 101L, 2L), (info.Channel, info.FirstRecordId, info.LastRecordId, info.RecordCount));
    }

    [Fact]
    public void A_huge_record_size_cannot_wrap_around_and_end_the_scan()
    {
        var writer = new EvtxWriter().Add(Rc4(100)).Add(Rc4(101));
        var chunk = writer.Chunk();
        BinaryPrimitives.WriteUInt32LittleEndian(chunk.AsSpan(writer.RecordOffsets[1] + 4), 0x7FFFFFF0);
        var path = Save("huge.evtx", EvtxWriter.File(0, chunk));
        var stats = new ReadStats();
        var found = Read(path, stats);
        output.WriteLine(stats.ToString());
        Assert.Single(found);
        Assert.Equal(1, stats.BadRecords);
        // The scanner keeps going as well, and says the file was only partly read.
        var info = new EvtxFileReader().Inspect(path);
        var result = Scanner.Scan(new EvtxFileReader(), [info], "t", new ScanOptions());
        Assert.Equal(FileState.Error, result.FileResults[path].State);
        Assert.Contains("unreadable records skipped", result.FileResults[path].Message);
        Assert.Equal(1, result.TotalHits);
        Assert.True(result.Incomplete);
    }

    [Fact]
    public void Nested_binary_xml_cannot_explode()
    {
        var path = Save("bomb.evtx", EvtxWriter.File(0, new EvtxWriter().AddNestedBomb(1, 400).Add(Rc4(2)).Chunk()));
        var clock = Stopwatch.StartNew();
        var stats = new ReadStats();
        var found = Read(path, stats, Queries.Kerberos, new EvtxQuery("all 4769", Channels.Security, "", null, EventIds: new HashSet<int> { 4769 }));
        output.WriteLine($"{clock.ElapsedMilliseconds} ms, {stats}");
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(5));
        Assert.Equal(1, stats.BadRecords);
        Assert.Contains("nested", stats.FirstError, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(found, f => f.Event.RecordId == 2);
    }

    [Fact]
    public void A_value_that_does_not_decode_keeps_the_record()
    {
        var badTime = new byte[16];
        BinaryPrimitives.WriteUInt16LittleEndian(badTime, 2026);
        BinaryPrimitives.WriteUInt16LittleEndian(badTime.AsSpan(2), 13); // month 13
        var badSid = new byte[] { 1, 200, 0, 0, 0, 0, 0, 5, 1, 2, 3, 4 }; // claims 200 sub-authorities
        var path = Save("values.evtx", EvtxWriter.File(0, new EvtxWriter().Add(Rc4(7, "bob",
            new EvtxWriter.Field("When", 0x12, badTime), new EvtxWriter.Field("Who", 0x13, badSid))).Chunk()));
        var stats = new ReadStats();
        var query = Queries.Kerberos with { Fields = [.. Queries.KerberosFields, "When", "Who"] };
        var found = Read(path, stats, query);
        output.WriteLine(stats.ToString());
        var e = Assert.Single(found).Event;
        Assert.Equal(0, stats.BadRecords);
        Assert.Equal(Convert.ToHexString(badTime), e["When"]);
        Assert.Equal(Convert.ToHexString(badSid), e["Who"]);
    }

    [Fact]
    public void Records_past_a_stale_free_offset_are_recovered_only_in_sequence()
    {
        var writer = new EvtxWriter().Add(Rc4(50)).Add(Rc4(51)).Add(Rc4(99));
        // The header says the chunk ends after the first record, like a log copied while Windows was writing.
        var chunk = writer.Chunk(free: writer.RecordOffsets[1]);
        var path = Save("dirty.evtx", EvtxWriter.File(0, chunk));
        var stats = new ReadStats();
        var found = Read(path, stats);
        output.WriteLine(stats.ToString());
        // 51 continues the sequence and is recovered, 99 does not and is left alone.
        Assert.Equal([50L, 51L], found.Select(f => f.Event.RecordId));
        Assert.Equal(1, stats.RecordsPastFree);
    }

    [Fact]
    public void A_wrong_checksum_is_counted_but_the_records_are_still_read()
    {
        var writer = new EvtxWriter().Add(Rc4(1)).Add(Rc4(2));
        var chunk = writer.Chunk();
        // Change one character of the computer name in the second record, after the checksum was written.
        var at = chunk.AsSpan(writer.RecordOffsets[1]).IndexOf(EvtxWriter.Utf16("DC01.lab"));
        chunk[writer.RecordOffsets[1] + at] = (byte)'X';
        var stats = new ReadStats();
        var found = Read(Save("crc.evtx", EvtxWriter.File(0, chunk)), stats);
        Assert.Equal(1, stats.ChecksumErrors);
        Assert.Equal(2, found.Count);
    }

    [Fact]
    public void A_wrapped_log_is_read_from_its_oldest_chunk()
    {
        Assert.Equal([(1L, 2), (0L, 1)], EvtxFileReader.Blocks(3, 1));
        Assert.Equal([(0L, 3)], EvtxFileReader.Blocks(3, 0));
        // A header number past the end counts around the file.
        Assert.Equal([(1L, 2), (0L, 1)], EvtxFileReader.Blocks(3, 7));
        var older = new EvtxWriter().Add(Rc4(10)).Chunk(firstNumber: 10);
        var newer = new EvtxWriter().Add(Rc4(20)).Chunk(firstNumber: 20);
        // Physical order: newer first, the header names chunk 1 (older) as the oldest.
        var path = Save("wrapped.evtx", EvtxWriter.File(1, newer, older));
        Assert.Equal([10L, 20L], Read(path, new ReadStats()).Select(f => f.Event.RecordId));
    }

    [Fact]
    public void Several_chunk_workers_give_the_same_result()
    {
        var chunks = Enumerable.Range(0, 6).Select(c =>
        {
            var w = new EvtxWriter();
            for (var i = 0; i < 20; i++) w.Add(Rc4(c * 100 + i));
            return w.Chunk(firstNumber: c * 100 + 1);
        }).ToArray();
        var path = Save("many.evtx", EvtxWriter.File(0, chunks));
        var one = new EvtxFileReader { ChunkWorkers = 1 }.ReadAll(path, [Queries.Kerberos], CancellationToken.None).Select(f => f.Event.RecordId).ToList();
        var four = new EvtxFileReader { ChunkWorkers = 4 }.ReadAll(path, [Queries.Kerberos], CancellationToken.None).Select(f => f.Event.RecordId).ToList();
        Assert.Equal(120, one.Count);
        Assert.Equal(one, four);
    }

    [Fact]
    public void Cancelling_a_parser_scan_is_logged()
    {
        var path = Save("c.evtx", EvtxWriter.File(0, new EvtxWriter().Add(Rc4(1)).Chunk()));
        var log = DiagLog.Create("test", Path.Combine(_dir, "c.log"));
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var reader = new EvtxFileReader();
        var result = Scanner.Scan(reader, [reader.Inspect(path)], "t", new ScanOptions(Log: log), cancellationToken: cts.Token);
        log.Dispose();
        Assert.True(result.Cancelled);
        Assert.True(result.Incomplete);
        Assert.Contains("built-in .evtx reader", File.ReadAllText(log.Path));
    }
}
