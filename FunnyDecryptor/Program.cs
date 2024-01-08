using System.Security.Cryptography;

Console.WriteLine("Enter your key:");
var key = Convert.FromHexString(Console.ReadLine()!);
using var rsa = RSA.Create();
rsa.ImportRSAPrivateKey(key, out _);

Console.WriteLine("Enter root path:");
var path = Console.ReadLine();

Console.WriteLine("Wait.");

var crypted = ScanDirectories(path!)
    .SelectMany(Directory.EnumerateFiles)
    .Where(x => Path.GetExtension(x) == ".FUNNY");


var prefix = new ReadOnlyMemory<byte>("FUNNY"u8.ToArray());

var def = Console.ForegroundColor;

foreach (var file in crypted)
{
    var name = Path.GetFileName(file);
    try
    {
        var fileSpan = File.ReadAllBytes(file).AsSpan();
        var woPref = fileSpan[prefix.Length..];
        var map = GetChunks(ref woPref);
        var chunks = new byte[map.Length][];

        // start offset = prefix + 4 + (map.Count * 16)
        // so if `map.Count == 2` it is 41
        // 41

        for (var i = 0; i < chunks.Length; i++)
        {
            var mapSeg = map[i];
            chunks[i] = rsa.Decrypt(fileSpan[(int)(mapSeg.Start)..(int)(mapSeg.End)], RSAEncryptionPadding.Pkcs1);
        }

        File.WriteAllBytes(file.Replace(name, name.Replace(".FUNNY", "")), chunks.SelectMany(x => x).ToArray());
        File.Delete(file);

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"{name} - decrypted");
        Console.ForegroundColor = def;
    }
    catch
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"{name} - not decrypted");
        Console.ForegroundColor = def;
    }
}

Console.WriteLine("Done.");

return;

static MapSegment[] GetChunks(ref Span<byte> file)
{
    var count = BitConverter.ToInt32(file[..4]);
    var result = new MapSegment[count];

    /*
     * MAP INFO:
     *
     * [ PR ][     4 bytes    ]  [                                  16 bytes                                  ]
     * [ EF ]| TOTAL SEGMENTS |  [                                   SEGMENT                                  ]
     * [ IX ]|      SIZE      |  [                START               ||||                END                 ]
     * [    ][0], [1], [2], [3], [x], [x], [x], [x], [x], [x], [x], [x], [x], [x], [x], [x], [x], [x], [x], [x]
     */

    var offset = 4;

    for (var i = 0; i < count; i++)
    {
        result[i] = new MapSegment(BitConverter.ToInt64(file.Slice(offset, 8)), BitConverter.ToInt64(file.Slice(offset += 8, 8)));
        offset += 8;
    }

    return result;
}

static IEnumerable<string> ScanDirectories(string pathDir)
{
    yield return pathDir;
    IEnumerable<string> dirs;

    try
    {
        dirs = Directory.EnumerateDirectories(pathDir);
    }
    catch
    {
        dirs = Enumerable.Empty<string>();
    }

    foreach (var dirsLst in dirs.SelectMany(ScanDirectories))
    {
        yield return dirsLst;
    }
}

internal readonly struct MapSegment (in long start, in long end)
{
    public readonly long Start = start;
    public readonly long End = end;
}