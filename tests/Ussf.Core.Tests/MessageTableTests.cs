using Xunit;

namespace Ussf.Core.Tests;

/// <summary>
/// Locks the message table (types, usage lines, notes) so any accidental edit to the
/// user-facing strings is caught. These are the port's equivalents of the original
/// <c>$USSF_Messages</c> entries defined in <c>SetMessageAndErrorContent</c>.
/// </summary>
public class MessageTableTests
{
    [Fact]
    public void Table_Has16Contiguous_Entries()
    {
        Assert.Equal(16, InstallerDetector.Messages.Count);
        for (int i = 1; i <= 16; i++)
            Assert.True(InstallerDetector.Messages.ContainsKey(i), $"missing message {i}");
    }

    [Theory]
    [MemberData(nameof(ExpectedMessages))]
    public void Message_HasExpectedContent(int key, string ext, string type, string usage, string notes)
    {
        var msg = InstallerDetector.Messages[key];
        Assert.Equal(ext, msg.Extension);
        Assert.Equal(type, msg.Type);
        Assert.Equal(usage, msg.Usage);
        Assert.Equal(notes, msg.Notes);
    }

    public static IEnumerable<object[]> ExpectedMessages() => new[]
    {
        new object[] { 1, ".inf", "Information or Installation file", "rundll32.exe setupapi,InstallHinfSection DefaultInstall 132 {filename}", "N/A" },
        new object[] { 2, ".reg", "Registry file", "regedit.exe /s \"{filename}\"", "" },
        new object[] { 3, ".exe", "NSIS Package", "\"{filename}\" /S", "" },
        new object[] { 4, ".exe", "Inno Setup Package", "\"{filename}\" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-", "" },
        new object[] { 6, ".exe", "InstallShield 2003 Package", "\"{filename}\" /s /v\"/qb\"", "You can also try to get the .MSI file from the Temp directory during installation, then install with: msiexec.exe /i setup.msi /qb" },
        new object[] { 7, ".exe", "Wise Installer Package", "\"{filename}\" /s", "" },
        new object[] { 8, ".exe", "Self-Extracting RAR Archive", "\"{filename}\" /s", "The RAR comment contains the installation script." },
        new object[] { 9, ".exe", "Self-Extracting Microsoft CAB Archive", "", "Extract the archive with UniExtract or another unpacker." },
        new object[] { 10, ".exe", "Self-Extracting ZIP Archive", "\"{filename}\" /s", "" },
        new object[] { 11, ".exe", "7-Zip Installer Package", "\"{filename}\" /s", "" },
        new object[] { 12, ".exe", "Unknown 7-Zip Archive", "", "Extract with 7-Zip" },
        new object[] { 13, ".exe", "Unknown ZIP Archive", "", "Extract with unzip" },
        new object[] { 14, ".exe", "Self-Extracting WinZip Archive", "\"{filename}\" /s", "" },
        new object[] { 15, ".exe", "UPX Packed", "", "Unpack with UPX" },
        new object[] { 16, ".msi", "MSI File", "msiexec.exe /i \"{filename}\" /qb", "" },
    };

    [Fact]
    public void Message5_InstallshieldAfw_IsDefinedButUnreachable()
    {
        // The AFW message exists in the table (fidelity with the original message 5), but no
        // detection path currently returns 5 — both InstallShield variants collapse to 6.
        // This test documents that gap; see the evaluation notes.
        Assert.True(InstallerDetector.Messages.ContainsKey(5));
        Assert.Equal("Installshield AFW Package", InstallerDetector.Messages[5].Type);
    }

    [Fact]
    public void FilenamePlaceholder_IsSubstitutable()
    {
        var usage = InstallerDetector.Messages[3].Usage.Replace("{filename}", "setup.exe");
        Assert.Equal("\"setup.exe\" /S", usage);
    }

    [Fact]
    public void ExeSignatures_AreInDocumentedPriorityOrder()
    {
        var msgs = InstallerDetector.ExeSignatures.Select(s => s.Msg).ToArray();
        Assert.Equal(new[] { 3, 4, 6, 6, 7, 8, 9, 11, 14, 10 }, msgs);
    }
}
