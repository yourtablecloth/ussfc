using Xunit;

namespace Ussf.Core.Tests;

/// <summary>
/// Covers the deep PE-content scan (<see cref="InstallerDetector.DetectExeKindFromBuffer"/> and
/// <see cref="InstallerDetector.DetectExeKindFromStream"/>) that replaces the original PEiD lookup
/// with case-sensitive byte-signature matching.
/// </summary>
public class ExeDeepScanTests
{
    [Theory]
    [InlineData("NullsoftInst", 3)]
    [InlineData("Inno Setup", 4)]
    [InlineData("InstallShield", 6)]
    [InlineData("Installshield", 6)]
    [InlineData("WiseMain", 7)]
    [InlineData("WinZip Self-Extractor", 14)]
    public void AsciiSignatures_MapToExpectedMessage(string signature, int expected)
    {
        var data = TestData.ExeWith(signature);
        Assert.Equal(expected, InstallerDetector.DetectExeKindFromBuffer(data));
    }

    [Fact]
    public void RarMagic_MapsToRarSfx() =>
        Assert.Equal(8, InstallerDetector.DetectExeKindFromBuffer(TestData.ExeWith(TestData.Rar)));

    [Fact]
    public void CabMagic_MapsToCabSfx() =>
        Assert.Equal(9, InstallerDetector.DetectExeKindFromBuffer(TestData.ExeWith(TestData.Cab)));

    [Fact]
    public void SevenZipMagic_InsidePe_MapsToInstaller() =>
        Assert.Equal(11, InstallerDetector.DetectExeKindFromBuffer(TestData.ExeWith(TestData.SevenZip)));

    [Fact]
    public void ZipMagic_InsidePe_MapsToZipSfx() =>
        Assert.Equal(10, InstallerDetector.DetectExeKindFromBuffer(TestData.ExeWith(TestData.Zip)));

    [Fact]
    public void UpxSections_TakePrecedence_OverEverything()
    {
        // A UPX-packed PE that also happens to contain a lower-priority signature still reports UPX.
        var upx = TestData.UpxExe();
        var withSig = TestData.Concat(upx, TestData.Ascii("Inno Setup"));
        Assert.Equal(15, InstallerDetector.DetectExeKindFromBuffer(withSig));
    }

    [Fact]
    public void PeWithNoKnownSignature_ReturnsUnrecognized() =>
        Assert.Equal(-7, InstallerDetector.DetectExeKindFromBuffer(TestData.ExeWith("nothing to see here")));

    [Fact]
    public void CabMagic_RequiresFourTrailingZeroBytes()
    {
        // "MSCF" followed by non-zero bytes is NOT the CAB signature the port matches
        // (the port's pattern is 4D 53 43 46 00 00 00 00). Keep the bytes right after
        // "MSCF" non-zero so no CAB signature is accidentally formed.
        var almostCab = TestData.Concat(TestData.Mz, TestData.Ascii("MSCFABCD"), new byte[16]);
        Assert.Equal(-7, InstallerDetector.DetectExeKindFromBuffer(almostCab));
    }

    [Theory]
    // Two signatures present at once: the higher-priority one (earlier in the table) must win.
    [InlineData("Inno Setup", "7z", 4)]      // Inno (prio 2) beats 7-Zip magic (prio 8)
    [InlineData("InstallShield", "wise", 6)] // InstallShield (prio 3) beats Wise (prio 5)
    public void WhenMultipleSignaturesMatch_HighestPriorityWins(string first, string second, int expected)
    {
        byte[] secondBytes = second switch
        {
            "7z" => TestData.SevenZip,
            "wise" => TestData.Ascii("WiseMain"),
            _ => throw new ArgumentOutOfRangeException(nameof(second)),
        };
        var data = TestData.Concat(TestData.Mz, TestData.Ascii(first), new byte[16], secondBytes, new byte[16]);
        Assert.Equal(expected, InstallerDetector.DetectExeKindFromBuffer(data));
    }

    [Fact]
    public void RarBeforeZip_RarWins()
    {
        var data = TestData.Concat(TestData.Mz, TestData.Rar, new byte[16], TestData.Zip, new byte[16]);
        Assert.Equal(8, InstallerDetector.DetectExeKindFromBuffer(data)); // RAR prio 6 < ZIP prio 10
    }

    // ---- stream path parity + chunk-boundary handling ----

    [Theory]
    [InlineData("NullsoftInst", 3)]
    [InlineData("Inno Setup", 4)]
    [InlineData("WinZip Self-Extractor", 14)]
    public void StreamPath_MatchesBufferPath(string signature, int expected)
    {
        var data = TestData.ExeWith(signature);
        using var ms = new MemoryStream(data);
        var head = InstallerDetector.ReadHeaderBytes(ms, InstallerDetector.HeaderLength);
        ms.Position = 0;
        Assert.Equal(expected, InstallerDetector.DetectExeKindFromStream(ms, head));
    }

    [Fact]
    public void StreamPath_DetectsSignature_StraddlingChunkBoundary()
    {
        // The stream scanner reads in 4 MB chunks with a carry-over tail. Place a signature so it
        // spans the boundary and confirm the overlap logic still finds it.
        const int chunk = 4 * 1024 * 1024;
        byte[] sig = TestData.Ascii("WinZip Self-Extractor");
        int start = chunk - sig.Length / 2;
        var data = new byte[chunk + 64];
        Array.Fill(data, (byte)0xAA);
        Array.Copy(sig, 0, data, start, sig.Length);

        using var ms = new MemoryStream(data);
        var head = new byte[64]; // non-UPX head
        Assert.Equal(14, InstallerDetector.DetectExeKindFromStream(ms, head));
    }

    [Fact]
    public void StreamPath_UpxHeadTakesPrecedence()
    {
        var upx = TestData.UpxExe();
        using var ms = new MemoryStream(upx);
        var head = InstallerDetector.ReadHeaderBytes(ms, InstallerDetector.HeaderLength);
        ms.Position = 0;
        Assert.Equal(15, InstallerDetector.DetectExeKindFromStream(ms, head));
    }
}
