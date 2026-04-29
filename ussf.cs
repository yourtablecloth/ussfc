#!/usr/bin/env dotnet

#:property Version=1.4.1.2
#:property AssemblyVersion=1.4.1.2
#:property FileVersion=1.4.1.2
#:property InformationalVersion=1.4.1.2

#:property PackageId=ussfc
#:property ToolCommandName=ussfc
#:property Authors=Jung-Hyun Nam
#:property Company=yourtablecloth
#:property Description=Universal Silent Setup Finder Console — identifies Windows installer types (NSIS, Inno, InstallShield, Wise, MSI, 7-Zip/CAB/ZIP/RAR SFX, UPX, etc.) and the silent-install command line for each. Ported from the original AutoIt USSF by Alexandru Avadanii.
#:property PackageProjectUrl=https://github.com/yourtablecloth/ussfc
#:property RepositoryUrl=https://github.com/yourtablecloth/ussfc
#:property RepositoryType=git
#:property PackageLicenseExpression=Apache-2.0
#:property PackageReadmeFile=README.md
#:property PackageTags=installer;silent-install;setup;nsis;inno-setup;installshield;wise;msi;7zip;cab;cli;dotnet-tool
#:property PackageRequireLicenseAcceptance=false

// Copyright 2025 Alexandru Avadanii
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Converted from AutoIt to C# Console Application.
// Converted and developed by Jung-Hyun Nam.
// Original project: https://github.com/alexandruavadanii/USSF

using System.Collections.ObjectModel;
using System.Text;
using System.Text.Json;

const string Version = "1.4.1.2";

ReadOnlyDictionary<int, (string Extension, string Type, string Usage, string Notes)> Messages = new ReadOnlyDictionary<int, (string, string, string, string)>(new Dictionary<int, (string, string, string, string)>
{
    {1, (".inf", "Information or Installation file", "rundll32.exe setupapi,InstallHinfSection DefaultInstall 132 {filename}", "N/A")},
    {2, (".reg", "Registry file", "regedit.exe /s \"{filename}\"", "")},
    {3, (".exe", "NSIS Package", "\"{filename}\" /S", "")},
    {4, (".exe", "Inno Setup Package", "\"{filename}\" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-", "")},
    {5, (".exe", "Installshield AFW Package", "", "Extract the installation file with UniExtract or another unpacker. The unpacked archive should be either .CAB or .MSI based. Next only for .CAB based files: Create an installation with this command: {filename} /r /f1\"X:\\setup.iss\" Now you can perform a silent installation using the ISS file: {filename} /s /f1\"X:\\setup.iss\" Next only for .MSI based files: msiexec.exe /i setup.msi /qb")},
    {6, (".exe", "InstallShield 2003 Package", "\"{filename}\" /s /v\"/qb\"", "You can also try to get the .MSI file from the Temp directory during installation, then install with: msiexec.exe /i setup.msi /qb")},
    {7, (".exe", "Wise Installer Package", "\"{filename}\" /s", "")},
    {8, (".exe", "Self-Extracting RAR Archive", "\"{filename}\" /s", "The RAR comment contains the installation script.")},
    {9, (".exe", "Self-Extracting Microsoft CAB Archive", "", "Extract the archive with UniExtract or another unpacker.")},
    {10, (".exe", "Self-Extracting ZIP Archive", "\"{filename}\" /s", "")},
    {11, (".exe", "7-Zip Installer Package", "\"{filename}\" /s", "")},
    {12, (".exe", "Unknown 7-Zip Archive", "", "Extract with 7-Zip")},
    {13, (".exe", "Unknown ZIP Archive", "", "Extract with unzip")},
    {14, (".exe", "Self-Extracting WinZip Archive", "\"{filename}\" /s", "")},
    {15, (".exe", "UPX Packed", "", "Unpack with UPX")},
    {16, (".msi", "MSI File", "msiexec.exe /i \"{filename}\" /qb", "")}
});

bool jsonOutput = false;
bool showHelp = false;
bool showVersion = false;
string? filePath = null;

foreach (var arg in args)
{
    if (string.Equals(arg, "--json", StringComparison.Ordinal))
        jsonOutput = true;
    else if (string.Equals(arg, "--help", StringComparison.Ordinal)
        || string.Equals(arg, "-h", StringComparison.Ordinal)
        || string.Equals(arg, "-?", StringComparison.Ordinal))
        showHelp = true;
    else if (string.Equals(arg, "--version", StringComparison.Ordinal)
        || string.Equals(arg, "-v", StringComparison.Ordinal))
        showVersion = true;
    else if (filePath == null)
        filePath = arg;
}

if (showVersion)
{
    Console.WriteLine($"ussfc {Version}");
    return;
}

if (showHelp)
{
    PrintHelp(Version);
    return;
}

bool stdinMode = filePath == null && Console.IsInputRedirected;

if (filePath == null && !stdinMode)
{
    Console.WriteLine("Usage: ussfc [--json] [--help] <file_path>");
    return;
}

string displayName;
string? extension;
byte[] headerBuffer;

// Sentinel: shallow detection saw MZ; caller must run a deep PE-content scan.
const int ExeNeedsDeepScan = 0;

// Cap on how many bytes to buffer from stdin when deep-scanning a piped EXE.
const int MaxStdinDeepScanBytes = 64 * 1024 * 1024;

// Native equivalents of the original PEiD-based branches in TestExeFile (ussf.au3).
// Order = priority: first match wins, mirroring the Select/Case order in the original.
// Strings are matched as case-sensitive ASCII byte sequences inside the PE binary.
(byte[] Pattern, int Msg, string Label)[] ExeSignatures = new (byte[], int, string)[]
{
    (Encoding.ASCII.GetBytes("NullsoftInst"),                      3, "NSIS"),
    (Encoding.ASCII.GetBytes("Inno Setup"),                        4, "Inno Setup"),
    (Encoding.ASCII.GetBytes("InstallShield"),                     6, "InstallShield"),
    (Encoding.ASCII.GetBytes("Installshield"),                     6, "InstallShield (alt case)"),
    (Encoding.ASCII.GetBytes("WiseMain"),                          7, "Wise Installer"),
    (new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07 },            8, "RAR SFX"),
    (new byte[] { 0x4D, 0x53, 0x43, 0x46, 0x00, 0x00, 0x00, 0x00 }, 9, "CAB SFX"),
    (new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C },           11, "7-Zip"),
    (Encoding.ASCII.GetBytes("WinZip Self-Extractor"),            14, "WinZip SFX"),
    (new byte[] { 0x50, 0x4B, 0x03, 0x04 },                       10, "ZIP SFX"),
};

int messageNumber;

if (stdinMode)
{
    displayName = "<stdin>";
    extension = null;
    using var stdin = Console.OpenStandardInput();
    headerBuffer = ReadHeaderBytes(stdin, 4096);
    messageNumber = DetectFromBytes(headerBuffer, extension);
    if (messageNumber == ExeNeedsDeepScan)
    {
        var fullData = AppendStreamUpTo(stdin, headerBuffer, MaxStdinDeepScanBytes);
        messageNumber = DetectExeKindFromBuffer(fullData);
    }
}
else
{
    if (!File.Exists(filePath!))
    {
        if (jsonOutput)
            WriteJsonError(filePath!, null, "File does not exist.");
        else
            Console.WriteLine("File does not exist.");
        return;
    }
    displayName = Path.GetFileName(filePath!);
    extension = Path.GetExtension(filePath!).ToLowerInvariant();
    using var fs = new FileStream(filePath!, FileMode.Open, FileAccess.Read);
    headerBuffer = ReadHeaderBytes(fs, 4096);
    messageNumber = DetectFromBytes(headerBuffer, extension);
    if (messageNumber == ExeNeedsDeepScan)
    {
        fs.Position = 0;
        messageNumber = DetectExeKindFromStream(fs, headerBuffer);
    }
}
if (messageNumber > 0 && Messages.ContainsKey(messageNumber))
{
    var msg = Messages[messageNumber];
    if (jsonOutput)
    {
        using var stdout = Console.OpenStandardOutput();
        using var writer = new Utf8JsonWriter(stdout, new JsonWriterOptions { Indented = true });
        writer.WriteStartObject();
        writer.WriteString("file", stdinMode ? "<stdin>" : filePath);
        if (extension != null)
            writer.WriteString("extension", extension);
        writer.WriteString("type", msg.Type);
        writer.WriteString("usage", msg.Usage.Replace("{filename}", displayName));
        writer.WriteString("notes", msg.Notes.Replace("{filename}", displayName));
        writer.WriteEndObject();
        writer.Flush();
        stdout.WriteByte((byte)'\n');
    }
    else
    {
        Console.WriteLine($"File: {(stdinMode ? "<stdin>" : filePath)}");
        if (extension != null)
            Console.WriteLine($"Extension: {extension}");
        Console.WriteLine($"Type: {msg.Type}");
        Console.WriteLine($"Usage: {msg.Usage.Replace("{filename}", displayName)}");
        if (!string.IsNullOrEmpty(msg.Notes))
            Console.WriteLine($"Notes: {msg.Notes.Replace("{filename}", displayName)}");
    }
}
else
{
    string errorMsg = messageNumber switch
    {
        -1 => "Corrupted EXE: invalid MZ header.",
        -2 => "Corrupted MSI: invalid header.",
        -3 => "Invalid REG file format.",
        -7 => "Windows PE file detected, but not a recognized installer or archive.",
        _ => "Unknown or unsupported file type."
    };

    if (jsonOutput)
        WriteJsonError(stdinMode ? "<stdin>" : filePath!, extension, errorMsg);
    else
        Console.WriteLine($"Error: {errorMsg}");
}

static void PrintHelp(string version)
{
    Console.WriteLine($"ussfc {version} - Universal Silent Setup Finder / Console");
    Console.WriteLine();
    Console.WriteLine("Usage:");
    Console.WriteLine("  ussfc [options] <file_path>");
    Console.WriteLine("  <data> | ussfc [options]");
    Console.WriteLine();
    Console.WriteLine("Arguments:");
    Console.WriteLine("  <file_path>   Path to the installer or file to analyze.");
    Console.WriteLine();
    Console.WriteLine("Options:");
    Console.WriteLine("  --json        Output result as JSON instead of human-readable text.");
    Console.WriteLine("  --help, -h    Show this help message.");
    Console.WriteLine("  --version, -v Show version information.");
    Console.WriteLine();
    Console.WriteLine("Supported file types:");
    Console.WriteLine("  .inf   Information / Installation file");
    Console.WriteLine("  .reg   Registry file");
    Console.WriteLine("  .msi   Windows Installer package");
    Console.WriteLine("  .exe   Executables (NSIS, Inno Setup, InstallShield, Wise, 7-Zip, WinZip, UPX, etc.)");
    Console.WriteLine();
    Console.WriteLine("Examples:");
    Console.WriteLine("  ussfc setup.exe");
    Console.WriteLine("  ussfc --json setup.msi");
    Console.WriteLine("  cat setup.exe | ussfc --json");
}

static void WriteJsonError(string filePath, string? extension, string error)
{
    using var stdout = Console.OpenStandardOutput();
    using var writer = new Utf8JsonWriter(stdout, new JsonWriterOptions { Indented = true });
    writer.WriteStartObject();
    writer.WriteString("file", filePath);
    if (extension != null)
        writer.WriteString("extension", extension);
    writer.WriteString("error", error);
    writer.WriteEndObject();
    writer.Flush();
    stdout.WriteByte((byte)'\n');
}

static byte[] ReadHeaderBytes(Stream stream, int count)
{
    byte[] buffer = new byte[count];
    int offset = 0;
    while (offset < count)
    {
        int read = stream.Read(buffer, offset, count - offset);
        if (read == 0) break;
        offset += read;
    }
    if (offset < count)
        return buffer[..offset];
    return buffer;
}

static bool HeaderMatches(byte[] header, string expectedHex)
{
    int length = expectedHex.Length / 2;
    if (header.Length < length)
        return false;
    string hex = BitConverter.ToString(header, 0, length).Replace("-", "");
    return hex.Equals(expectedHex, StringComparison.OrdinalIgnoreCase);
}

static bool IsRegContent(byte[] header)
{
    // UTF-16 LE BOM (FF FE)
    if (header.Length >= 2 && header[0] == 0xFF && header[1] == 0xFE)
    {
        string text = Encoding.Unicode.GetString(header).TrimStart('\uFEFF');
        return text.StartsWith("Windows Registry Editor Version 5.00", StringComparison.Ordinal) ||
               text.StartsWith("REGEDIT4", StringComparison.Ordinal);
    }
    // UTF-8 (with or without BOM)
    string utf8 = Encoding.UTF8.GetString(header).TrimStart('\uFEFF');
    return utf8.StartsWith("Windows Registry Editor Version 5.00", StringComparison.Ordinal) ||
           utf8.StartsWith("REGEDIT4", StringComparison.Ordinal);
}

static bool IsInfContent(byte[] header)
{
    string text = Encoding.UTF8.GetString(header).TrimStart('\uFEFF').TrimStart();
    return text.StartsWith('[');
}

static int DetectFromBytes(byte[] header, string? extension)
{
    // Binary signature detection (extension-agnostic)
    if (HeaderMatches(header, "D0CF11E0A1B11AE1000000000000000000000000000000003E000300FEFF090006"))
        return 16; // MSI (OLE Compound Document)

    // Raw archives (file IS the archive, not an SFX): mirror original messages 12/13.
    if (header.Length >= 6
        && header[0] == 0x37 && header[1] == 0x7A
        && header[2] == 0xBC && header[3] == 0xAF
        && header[4] == 0x27 && header[5] == 0x1C)
        return 12; // Unknown 7-Zip Archive

    if (header.Length >= 4
        && header[0] == 0x50 && header[1] == 0x4B
        && header[2] == 0x03 && header[3] == 0x04)
        return 13; // Unknown ZIP Archive

    if (HeaderMatches(header, "4D5A")) // MZ -> EXE: caller performs deep scan
        return ExeNeedsDeepScan;

    // Text-based detection
    if (IsRegContent(header))
        return 2;

    // Extension fallback
    switch (extension)
    {
        case ".inf": return 1;
        case ".msi": return -2; // MSI without valid header -> corrupted
        case ".exe": return -1; // EXE without MZ header -> corrupted
        case ".reg": return -3; // REG without valid header -> invalid
    }

    // Heuristic: INF-like text (no extension available)
    if (IsInfContent(header))
        return 1;

    return -6; // Not supported
}

// PE section-table inspection for UPX0/UPX1/UPX2 — exact, not heuristic.
static bool HasUpxSections(byte[] head)
{
    if (head.Length < 0x40 || head[0] != (byte)'M' || head[1] != (byte)'Z')
        return false;
    int peOffset = BitConverter.ToInt32(head, 0x3C);
    if (peOffset < 0 || peOffset + 24 > head.Length)
        return false;
    if (head[peOffset] != (byte)'P' || head[peOffset + 1] != (byte)'E')
        return false;
    int numSections = BitConverter.ToUInt16(head, peOffset + 6);
    int sizeOfOptHdr = BitConverter.ToUInt16(head, peOffset + 20);
    int sectionTable = peOffset + 24 + sizeOfOptHdr;
    for (int i = 0; i < numSections; i++)
    {
        int nameOff = sectionTable + i * 40;
        if (nameOff + 4 > head.Length) break;
        if (head[nameOff] == (byte)'U' && head[nameOff + 1] == (byte)'P' && head[nameOff + 2] == (byte)'X'
            && (head[nameOff + 3] == (byte)'0' || head[nameOff + 3] == (byte)'1' || head[nameOff + 3] == (byte)'2'))
            return true;
    }
    return false;
}

int PickFromHits(bool[] hits)
{
    for (int i = 0; i < ExeSignatures.Length; i++)
        if (hits[i]) return ExeSignatures[i].Msg;
    return -7; // PE but no recognized installer/archive signature
}

// Deep scan when input is a stream we can rewind (file).
int DetectExeKindFromStream(FileStream fs, byte[] head)
{
    if (HasUpxSections(head))
        return 15;

    var hits = new bool[ExeSignatures.Length];
    int maxPattern = 0;
    foreach (var s in ExeSignatures)
        if (s.Pattern.Length > maxPattern) maxPattern = s.Pattern.Length;
    int overlap = Math.Max(maxPattern - 1, 0);

    const int chunkSize = 4 * 1024 * 1024; // 4 MB
    var buf = new byte[chunkSize];
    int prevTail = 0;

    while (true)
    {
        int read = fs.Read(buf, prevTail, buf.Length - prevTail);
        if (read == 0) break;
        int valid = prevTail + read;
        var span = new ReadOnlySpan<byte>(buf, 0, valid);

        for (int i = 0; i < ExeSignatures.Length; i++)
        {
            if (hits[i]) continue;
            if (span.IndexOf(ExeSignatures[i].Pattern.AsSpan()) >= 0)
                hits[i] = true;
        }

        // Highest-priority hit found? Stop early.
        for (int i = 0; i < ExeSignatures.Length; i++)
        {
            if (hits[i]) return ExeSignatures[i].Msg;
        }

        if (read < buf.Length - prevTail) break; // EOF
        int tailLen = Math.Min(overlap, valid);
        if (tailLen > 0)
            Buffer.BlockCopy(buf, valid - tailLen, buf, 0, tailLen);
        prevTail = tailLen;
    }

    return PickFromHits(hits);
}

// Deep scan when input came from stdin (single buffered blob).
int DetectExeKindFromBuffer(byte[] data)
{
    if (HasUpxSections(data))
        return 15;
    var span = new ReadOnlySpan<byte>(data);
    var hits = new bool[ExeSignatures.Length];
    for (int i = 0; i < ExeSignatures.Length; i++)
    {
        if (span.IndexOf(ExeSignatures[i].Pattern.AsSpan()) >= 0)
            hits[i] = true;
    }
    return PickFromHits(hits);
}

// Drain `stream` (after the bytes already in `prefix`) up to `maxAdditional` more bytes.
static byte[] AppendStreamUpTo(Stream stream, byte[] prefix, int maxAdditional)
{
    using var ms = new MemoryStream();
    ms.Write(prefix, 0, prefix.Length);
    var buf = new byte[64 * 1024];
    int total = 0;
    while (total < maxAdditional)
    {
        int want = Math.Min(buf.Length, maxAdditional - total);
        int read = stream.Read(buf, 0, want);
        if (read == 0) break;
        ms.Write(buf, 0, read);
        total += read;
    }
    return ms.ToArray();
}
