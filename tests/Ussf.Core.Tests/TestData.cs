using System.Text;

namespace Ussf.Core.Tests;

/// <summary>
/// Builders for synthetic, in-memory file fixtures that trigger each detection
/// branch. Keeping these as byte arrays (rather than on-disk files) makes the
/// detection tests hermetic and fast.
/// </summary>
internal static class TestData
{
    public static readonly byte[] Mz = { 0x4D, 0x5A };

    public static readonly byte[] Rar = { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07 };
    public static readonly byte[] Cab = { 0x4D, 0x53, 0x43, 0x46, 0x00, 0x00, 0x00, 0x00 };
    public static readonly byte[] SevenZip = { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C };
    public static readonly byte[] Zip = { 0x50, 0x4B, 0x03, 0x04 };

    /// <summary>The full 33-byte OLE Compound Document header the port checks for an MSI.</summary>
    public static readonly byte[] MsiHeader =
        Convert.FromHexString("D0CF11E0A1B11AE1000000000000000000000000000000003E000300FEFF090006");

    public static byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);

    public static byte[] Concat(params byte[][] parts)
    {
        using var ms = new MemoryStream();
        foreach (var p in parts)
            ms.Write(p, 0, p.Length);
        return ms.ToArray();
    }

    private static readonly byte[] Pad64 = new byte[64];

    /// <summary>An MZ (PE) blob carrying <paramref name="signature"/> in its body.</summary>
    public static byte[] ExeWith(byte[] signature) => Concat(Mz, Pad64, signature, Pad64);

    public static byte[] ExeWith(string asciiSignature) => ExeWith(Ascii(asciiSignature));

    /// <summary>A minimal PE whose section table contains a <c>UPX0</c>/<c>UPX1</c> section.</summary>
    public static byte[] UpxExe()
    {
        var buf = new byte[0x200];
        buf[0] = 0x4D; buf[1] = 0x5A;                       // "MZ"
        BitConverter.GetBytes(0x40).CopyTo(buf, 0x3C);      // e_lfanew -> 0x40
        buf[0x40] = 0x50; buf[0x41] = 0x45;                 // "PE\0\0"
        BitConverter.GetBytes((ushort)2).CopyTo(buf, 0x46); // NumberOfSections
        BitConverter.GetBytes((ushort)0xE0).CopyTo(buf, 0x54); // SizeOfOptionalHeader
        int sectionTable = 0x40 + 24 + 0xE0;
        Ascii("UPX0").CopyTo(buf, sectionTable);
        Ascii("UPX1").CopyTo(buf, sectionTable + 40);
        return buf;
    }

    public static byte[] GoodMsi() => Concat(MsiHeader, new byte[512]);

    public static byte[] RegUtf8() =>
        Ascii("Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER]\r\n");

    public static byte[] RegEdit4() =>
        Ascii("REGEDIT4\r\n\r\n[HKEY_CURRENT_USER]\r\n");

    public static byte[] RegUtf16() =>
        Concat(new byte[] { 0xFF, 0xFE },
               Encoding.Unicode.GetBytes("Windows Registry Editor Version 5.00\r\n"));

    /// <summary>UTF-8 registry export prefixed with an EF BB BF byte-order mark.</summary>
    public static byte[] RegUtf8Bom() =>
        Concat(new byte[] { 0xEF, 0xBB, 0xBF },
               Ascii("Windows Registry Editor Version 5.00\r\n"));

    public static byte[] InfLike() => Ascii("[Version]\r\nSignature=\"$WINDOWS NT$\"\r\n");
}
