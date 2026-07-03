using Xunit;

namespace Ussf.Core.Tests;

/// <summary>
/// Covers <see cref="InstallerDetector.DetectFromBytes"/> — the shallow, header-plus-extension
/// classifier that mirrors the original AutoIt <c>ParseProgram</c> dispatch.
/// </summary>
public class DetectFromBytesTests
{
    [Fact]
    public void MsiOleHeader_IsDetected_RegardlessOfExtension()
    {
        Assert.Equal(16, InstallerDetector.DetectFromBytes(TestData.GoodMsi(), null));
        Assert.Equal(16, InstallerDetector.DetectFromBytes(TestData.GoodMsi(), ".exe"));
    }

    [Fact]
    public void RawSevenZipMagic_AtOffsetZero_ReturnsUnknown7Zip()
    {
        var data = TestData.Concat(TestData.SevenZip, new byte[32]);
        Assert.Equal(12, InstallerDetector.DetectFromBytes(data, null));
        // The raw-archive check runs before the extension switch.
        Assert.Equal(12, InstallerDetector.DetectFromBytes(data, ".exe"));
    }

    [Fact]
    public void RawZipMagic_AtOffsetZero_ReturnsUnknownZip()
    {
        var data = TestData.Concat(TestData.Zip, new byte[32]);
        Assert.Equal(13, InstallerDetector.DetectFromBytes(data, null));
        Assert.Equal(13, InstallerDetector.DetectFromBytes(data, ".exe"));
    }

    [Fact]
    public void MzHeader_ReturnsDeepScanSentinel()
    {
        var data = TestData.ExeWith("whatever");
        Assert.Equal(InstallerDetector.ExeNeedsDeepScan, InstallerDetector.DetectFromBytes(data, ".exe"));
        Assert.Equal(0, InstallerDetector.ExeNeedsDeepScan);
    }

    [Theory]
    [MemberData(nameof(RegForms))]
    public void RegistryContent_IsDetected_BeforeExtensionFallback(byte[] data)
    {
        // Even with a mismatched extension, valid reg content wins (content check precedes the switch).
        Assert.Equal(2, InstallerDetector.DetectFromBytes(data, ".txt"));
        Assert.Equal(2, InstallerDetector.DetectFromBytes(data, null));
    }

    public static IEnumerable<object[]> RegForms() => new[]
    {
        new object[] { TestData.RegUtf8() },
        new object[] { TestData.RegEdit4() },
        new object[] { TestData.RegUtf16() },
        new object[] { TestData.RegUtf8Bom() },
    };

    [Fact]
    public void InfExtension_ReturnsInf_WithoutContentCheck()
    {
        // The original returns message 1 for any .inf file, no content validation.
        Assert.Equal(1, InstallerDetector.DetectFromBytes(TestData.Ascii("not really an inf"), ".inf"));
    }

    [Fact]
    public void MsiExtension_WithoutOleHeader_IsCorrupt()
    {
        Assert.Equal(-2, InstallerDetector.DetectFromBytes(TestData.Ascii("not an OLE file"), ".msi"));
    }

    [Fact]
    public void ExeExtension_WithoutMz_IsCorrupt()
    {
        Assert.Equal(-1, InstallerDetector.DetectFromBytes(TestData.Ascii("no MZ here"), ".exe"));
    }

    [Fact]
    public void RegExtension_WithInvalidContent_IsInvalid()
    {
        Assert.Equal(-3, InstallerDetector.DetectFromBytes(TestData.Ascii("this is not a reg file"), ".reg"));
    }

    [Fact]
    public void NoExtension_InfLikeText_FallsBackToInfHeuristic()
    {
        Assert.Equal(1, InstallerDetector.DetectFromBytes(TestData.InfLike(), null));
    }

    [Fact]
    public void UnknownExtensionAndContent_IsUnsupported()
    {
        Assert.Equal(-6, InstallerDetector.DetectFromBytes(TestData.Ascii("random content"), ".xyz"));
    }

    [Fact]
    public void EmptyHeader_IsUnsupported()
    {
        Assert.Equal(-6, InstallerDetector.DetectFromBytes(Array.Empty<byte>(), null));
    }
}
