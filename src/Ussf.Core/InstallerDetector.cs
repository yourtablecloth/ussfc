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

namespace Ussf.Core;

/// <summary>
/// A single detected file-type entry: the reported extension, human type name,
/// silent-install usage line, and any extra notes. Occurrences of the token
/// <c>{filename}</c> in <see cref="Usage"/> / <see cref="Notes"/> are substituted
/// with the analyzed file's display name by the caller.
/// </summary>
public readonly record struct InstallerMessage(string Extension, string Type, string Usage, string Notes);

/// <summary>
/// Pure, side-effect-free installer/archive detection logic ported from the
/// original AutoIt <c>ussf.au3</c>. Every method here is deterministic and takes
/// its input as bytes/streams so it can be unit-tested without touching the
/// console, the filesystem, or any external tool.
/// </summary>
public static class InstallerDetector
{
    /// <summary>
    /// Sentinel returned by <see cref="DetectFromBytes"/> when it saw an <c>MZ</c>
    /// header: the caller must run a deep PE-content scan to classify the executable.
    /// </summary>
    public const int ExeNeedsDeepScan = 0;

    /// <summary>Cap on how many bytes to buffer from stdin when deep-scanning a piped EXE.</summary>
    public const int MaxStdinDeepScanBytes = 64 * 1024 * 1024;

    /// <summary>Number of leading bytes read as the "header" for shallow detection.</summary>
    public const int HeaderLength = 4096;

    /// <summary>
    /// The message table, keyed by the original AutoIt return code (1..16).
    /// Kept verbatim from the port so output is stable.
    /// </summary>
    public static ReadOnlyDictionary<int, InstallerMessage> Messages { get; } =
        new(new Dictionary<int, InstallerMessage>
        {
            {1, new(".inf", "Information or Installation file", "rundll32.exe setupapi,InstallHinfSection DefaultInstall 132 {filename}", "N/A")},
            {2, new(".reg", "Registry file", "regedit.exe /s \"{filename}\"", "")},
            {3, new(".exe", "NSIS Package", "\"{filename}\" /S", "")},
            {4, new(".exe", "Inno Setup Package", "\"{filename}\" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-", "")},
            {5, new(".exe", "Installshield AFW Package", "", "Extract the installation file with UniExtract or another unpacker. The unpacked archive should be either .CAB or .MSI based. Next only for .CAB based files: Create an installation with this command: {filename} /r /f1\"X:\\setup.iss\" Now you can perform a silent installation using the ISS file: {filename} /s /f1\"X:\\setup.iss\" Next only for .MSI based files: msiexec.exe /i setup.msi /qb")},
            {6, new(".exe", "InstallShield 2003 Package", "\"{filename}\" /s /v\"/qb\"", "You can also try to get the .MSI file from the Temp directory during installation, then install with: msiexec.exe /i setup.msi /qb")},
            {7, new(".exe", "Wise Installer Package", "\"{filename}\" /s", "")},
            {8, new(".exe", "Self-Extracting RAR Archive", "\"{filename}\" /s", "The RAR comment contains the installation script.")},
            {9, new(".exe", "Self-Extracting Microsoft CAB Archive", "", "Extract the archive with UniExtract or another unpacker.")},
            {10, new(".exe", "Self-Extracting ZIP Archive", "\"{filename}\" /s", "")},
            {11, new(".exe", "7-Zip Installer Package", "\"{filename}\" /s", "")},
            {12, new(".exe", "Unknown 7-Zip Archive", "", "Extract with 7-Zip")},
            {13, new(".exe", "Unknown ZIP Archive", "", "Extract with unzip")},
            {14, new(".exe", "Self-Extracting WinZip Archive", "\"{filename}\" /s", "")},
            {15, new(".exe", "UPX Packed", "", "Unpack with UPX")},
            {16, new(".msi", "MSI File", "msiexec.exe /i \"{filename}\" /qb", "")}
        });

    // Native equivalents of the original PEiD-based branches in TestExeFile (ussf.au3).
    // Order = priority: first match wins, mirroring the Select/Case order in the original.
    // Strings are matched as case-sensitive ASCII byte sequences inside the PE binary.
    private static readonly (byte[] Pattern, int Msg, string Label)[] _exeSignatures =
    {
        (Encoding.ASCII.GetBytes("NullsoftInst"),                       3, "NSIS"),
        (Encoding.ASCII.GetBytes("Inno Setup"),                         4, "Inno Setup"),
        (Encoding.ASCII.GetBytes("InstallShield"),                      6, "InstallShield"),
        (Encoding.ASCII.GetBytes("Installshield"),                      6, "InstallShield (alt case)"),
        (Encoding.ASCII.GetBytes("WiseMain"),                           7, "Wise Installer"),
        (new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07 },             8, "RAR SFX"),
        (new byte[] { 0x4D, 0x53, 0x43, 0x46, 0x00, 0x00, 0x00, 0x00 }, 9, "CAB SFX"),
        (new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C },            11, "7-Zip"),
        (Encoding.ASCII.GetBytes("WinZip Self-Extractor"),             14, "WinZip SFX"),
        (new byte[] { 0x50, 0x4B, 0x03, 0x04 },                        10, "ZIP SFX"),
    };

    /// <summary>The ordered EXE content signatures used by the deep scan (highest priority first).</summary>
    public static IReadOnlyList<(byte[] Pattern, int Msg, string Label)> ExeSignatures => _exeSignatures;

    /// <summary>Maps a (possibly negative) detection code to a human-readable error string.</summary>
    public static string DescribeError(int messageNumber) => messageNumber switch
    {
        -1 => "Corrupted EXE: invalid MZ header.",
        -2 => "Corrupted MSI: invalid header.",
        -3 => "Invalid REG file format.",
        -7 => "Windows PE file detected, but not a recognized installer or archive.",
        _ => "Unknown or unsupported file type."
    };

    /// <summary>Reads up to <paramref name="count"/> bytes from the start of the stream.</summary>
    public static byte[] ReadHeaderBytes(Stream stream, int count)
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

    /// <summary>True if the header begins with the given hex byte sequence (case-insensitive).</summary>
    public static bool HeaderMatches(byte[] header, string expectedHex)
    {
        int length = expectedHex.Length / 2;
        if (header.Length < length)
            return false;
        string hex = BitConverter.ToString(header, 0, length).Replace("-", "");
        return hex.Equals(expectedHex, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>True if the header is a Windows Registry export (UTF-16 LE or UTF-8).</summary>
    public static bool IsRegContent(byte[] header)
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

    /// <summary>Heuristic: the header looks like an INF/ini file (first non-space char is '[').</summary>
    public static bool IsInfContent(byte[] header)
    {
        string text = Encoding.UTF8.GetString(header).TrimStart('\uFEFF').TrimStart();
        return text.StartsWith('[');
    }

    /// <summary>
    /// Shallow, extension-aware classification from the file header. Returns a positive
    /// message number, a negative error code, or <see cref="ExeNeedsDeepScan"/> (0) when
    /// an <c>MZ</c> header requires a deep PE-content scan.
    /// </summary>
    public static int DetectFromBytes(byte[] header, string? extension)
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

    /// <summary>
    /// PE section-table inspection for UPX0/UPX1/UPX2 section names — exact, not heuristic.
    /// </summary>
    public static bool HasUpxSections(byte[] head)
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

    private static int PickFromHits(bool[] hits)
    {
        for (int i = 0; i < _exeSignatures.Length; i++)
            if (hits[i]) return _exeSignatures[i].Msg;
        return -7; // PE but no recognized installer/archive signature
    }

    /// <summary>
    /// Deep scan when the input is a stream we can read forward (e.g. a file). The stream
    /// is read from its current position to EOF; the caller is responsible for rewinding.
    /// <paramref name="head"/> supplies the already-read header for the UPX section check.
    /// </summary>
    public static int DetectExeKindFromStream(Stream stream, byte[] head)
    {
        if (HasUpxSections(head))
            return 15;

        var hits = new bool[_exeSignatures.Length];
        int maxPattern = 0;
        foreach (var s in _exeSignatures)
            if (s.Pattern.Length > maxPattern) maxPattern = s.Pattern.Length;
        int overlap = Math.Max(maxPattern - 1, 0);

        const int chunkSize = 4 * 1024 * 1024; // 4 MB
        var buf = new byte[chunkSize];
        int prevTail = 0;

        while (true)
        {
            int read = stream.Read(buf, prevTail, buf.Length - prevTail);
            if (read == 0) break;
            int valid = prevTail + read;
            var span = new ReadOnlySpan<byte>(buf, 0, valid);

            for (int i = 0; i < _exeSignatures.Length; i++)
            {
                if (hits[i]) continue;
                if (span.IndexOf(_exeSignatures[i].Pattern.AsSpan()) >= 0)
                    hits[i] = true;
            }

            // Highest-priority hit found? Stop early.
            for (int i = 0; i < _exeSignatures.Length; i++)
            {
                if (hits[i]) return _exeSignatures[i].Msg;
            }

            if (read < buf.Length - prevTail) break; // EOF
            int tailLen = Math.Min(overlap, valid);
            if (tailLen > 0)
                Buffer.BlockCopy(buf, valid - tailLen, buf, 0, tailLen);
            prevTail = tailLen;
        }

        return PickFromHits(hits);
    }

    /// <summary>Deep scan when the input came from stdin (a single buffered blob).</summary>
    public static int DetectExeKindFromBuffer(byte[] data)
    {
        if (HasUpxSections(data))
            return 15;
        var span = new ReadOnlySpan<byte>(data);
        var hits = new bool[_exeSignatures.Length];
        for (int i = 0; i < _exeSignatures.Length; i++)
        {
            if (span.IndexOf(_exeSignatures[i].Pattern.AsSpan()) >= 0)
                hits[i] = true;
        }
        return PickFromHits(hits);
    }

    /// <summary>Drain <paramref name="stream"/> (after the bytes already in <paramref name="prefix"/>) up to <paramref name="maxAdditional"/> more bytes.</summary>
    public static byte[] AppendStreamUpTo(Stream stream, byte[] prefix, int maxAdditional)
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

    /// <summary>
    /// End-to-end classification of a seekable stream (the file path): reads the header,
    /// runs shallow detection, and rewinds for a deep PE scan when required.
    /// </summary>
    public static int DetectFromStream(Stream seekableStream, string? extension)
    {
        byte[] header = ReadHeaderBytes(seekableStream, HeaderLength);
        int messageNumber = DetectFromBytes(header, extension);
        if (messageNumber == ExeNeedsDeepScan)
        {
            seekableStream.Position = 0;
            messageNumber = DetectExeKindFromStream(seekableStream, header);
        }
        return messageNumber;
    }

    /// <summary>
    /// End-to-end classification of an in-memory blob (the stdin path): runs shallow
    /// detection on the first <see cref="HeaderLength"/> bytes and a deep buffer scan when required.
    /// </summary>
    public static int DetectFromContent(byte[] content, string? extension)
    {
        byte[] header = content.Length > HeaderLength ? content[..HeaderLength] : content;
        int messageNumber = DetectFromBytes(header, extension);
        if (messageNumber == ExeNeedsDeepScan)
            messageNumber = DetectExeKindFromBuffer(content);
        return messageNumber;
    }
}
