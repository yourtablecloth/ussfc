using Xunit;

namespace Ussf.Core.Tests;

/// <summary>
/// Exercises the end-to-end wrappers the CLI uses: <see cref="InstallerDetector.DetectFromStream"/>
/// (file path) and <see cref="InstallerDetector.DetectFromContent"/> (stdin path). These combine the
/// shallow header check with the deep PE scan and must agree with each other.
/// </summary>
public class EndToEndDetectionTests
{
    public static IEnumerable<object[]> Cases() => new[]
    {
        new object[] { TestData.ExeWith("NullsoftInst"), ".exe", 3 },
        new object[] { TestData.ExeWith("Inno Setup"), ".exe", 4 },
        new object[] { TestData.ExeWith("InstallShield"), ".exe", 6 },
        new object[] { TestData.ExeWith("WiseMain"), ".exe", 7 },
        new object[] { TestData.ExeWith(TestData.Rar), ".exe", 8 },
        new object[] { TestData.ExeWith(TestData.Cab), ".exe", 9 },
        new object[] { TestData.ExeWith(TestData.SevenZip), ".exe", 11 },
        new object[] { TestData.ExeWith(TestData.Zip), ".exe", 10 },
        new object[] { TestData.ExeWith("WinZip Self-Extractor"), ".exe", 14 },
        new object[] { TestData.UpxExe(), ".exe", 15 },
        new object[] { TestData.ExeWith("plain pe, nothing special"), ".exe", -7 },
        new object[] { TestData.GoodMsi(), ".msi", 16 },
        new object[] { TestData.Concat(TestData.SevenZip, new byte[16]), ".7z", 12 },
        new object[] { TestData.Concat(TestData.Zip, new byte[16]), ".zip", 13 },
        new object[] { TestData.RegUtf8(), ".reg", 2 },
        new object[] { TestData.InfLike(), ".inf", 1 },
        new object[] { TestData.Ascii("unsupported"), ".xyz", -6 },
    };

    [Theory]
    [MemberData(nameof(Cases))]
    public void DetectFromContent_ClassifiesEndToEnd(byte[] content, string extension, int expected) =>
        Assert.Equal(expected, InstallerDetector.DetectFromContent(content, extension));

    [Theory]
    [MemberData(nameof(Cases))]
    public void DetectFromStream_AgreesWithDetectFromContent(byte[] content, string extension, int expected)
    {
        using var ms = new MemoryStream(content);
        Assert.Equal(expected, InstallerDetector.DetectFromStream(ms, extension));
    }

    [Fact]
    public void DetectFromContent_StdinLikeInput_HasNoExtension()
    {
        // stdin is analyzed with a null extension; an MZ + signature blob still classifies.
        Assert.Equal(3, InstallerDetector.DetectFromContent(TestData.ExeWith("NullsoftInst"), null));
    }

    [Fact]
    public void DetectFromContent_HeaderLongerThanHeaderLength_StillDeepScans()
    {
        // Signature sits well past the 4096-byte shallow header window; the deep scan must find it.
        var data = TestData.Concat(TestData.Mz, new byte[8192], TestData.Ascii("Inno Setup"), new byte[16]);
        Assert.Equal(4, InstallerDetector.DetectFromContent(data, ".exe"));
    }
}
