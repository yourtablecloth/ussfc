using System.Text;
using Xunit;

namespace Ussf.Core.Tests;

/// <summary>Covers the lower-level helpers used by the detector.</summary>
public class HelperTests
{
    [Fact]
    public void HeaderMatches_IsCaseInsensitive_OnPrefix()
    {
        var header = new byte[] { 0x4D, 0x5A, 0x90, 0x00 };
        Assert.True(InstallerDetector.HeaderMatches(header, "4d5a"));
        Assert.True(InstallerDetector.HeaderMatches(header, "4D5A"));
        Assert.False(InstallerDetector.HeaderMatches(header, "5A4D"));
    }

    [Fact]
    public void HeaderMatches_TooShortHeader_ReturnsFalse()
    {
        Assert.False(InstallerDetector.HeaderMatches(new byte[] { 0x4D }, "4D5A"));
    }

    [Theory]
    [MemberData(nameof(RegPositives))]
    public void IsRegContent_RecognizesRegistryExports(byte[] data) =>
        Assert.True(InstallerDetector.IsRegContent(data));

    public static IEnumerable<object[]> RegPositives() => new[]
    {
        new object[] { TestData.RegUtf8() },
        new object[] { TestData.RegEdit4() },
        new object[] { TestData.RegUtf16() },
        new object[] { TestData.RegUtf8Bom() },
    };

    [Fact]
    public void IsRegContent_RejectsNonRegistryText()
    {
        Assert.False(InstallerDetector.IsRegContent(TestData.Ascii("hello world")));
        Assert.False(InstallerDetector.IsRegContent(Array.Empty<byte>()));
    }

    [Theory]
    [InlineData("[Version]", true)]
    [InlineData("   \r\n [Section]", true)]
    [InlineData("key=value", false)]
    [InlineData("", false)]
    public void IsInfContent_DetectsLeadingBracket(string text, bool expected) =>
        Assert.Equal(expected, InstallerDetector.IsInfContent(TestData.Ascii(text)));

    [Fact]
    public void ReadHeaderBytes_ReturnsExactly_WhenStreamIsLonger()
    {
        using var ms = new MemoryStream(new byte[100]);
        Assert.Equal(10, InstallerDetector.ReadHeaderBytes(ms, 10).Length);
    }

    [Fact]
    public void ReadHeaderBytes_TrimsToAvailable_WhenStreamIsShorter()
    {
        using var ms = new MemoryStream(new byte[] { 1, 2, 3 });
        var header = InstallerDetector.ReadHeaderBytes(ms, 10);
        Assert.Equal(new byte[] { 1, 2, 3 }, header);
    }

    [Fact]
    public void ReadHeaderBytes_HandlesDripFedStream()
    {
        // A stream that returns one byte per Read must still be fully drained by the loop.
        using var slow = new OneByteAtATimeStream(new byte[] { 9, 8, 7, 6, 5 });
        var header = InstallerDetector.ReadHeaderBytes(slow, 5);
        Assert.Equal(new byte[] { 9, 8, 7, 6, 5 }, header);
    }

    [Fact]
    public void AppendStreamUpTo_ConcatenatesPrefixAndCapsRemainder()
    {
        var prefix = new byte[] { 1, 2 };
        using var ms = new MemoryStream(new byte[100]);
        var result = InstallerDetector.AppendStreamUpTo(ms, prefix, maxAdditional: 10);
        Assert.Equal(12, result.Length); // prefix (2) + at most 10 more
        Assert.Equal(1, result[0]);
        Assert.Equal(2, result[1]);
    }

    [Fact]
    public void AppendStreamUpTo_StopsAtEndOfStream()
    {
        var prefix = new byte[] { 1 };
        using var ms = new MemoryStream(new byte[] { 2, 3 });
        var result = InstallerDetector.AppendStreamUpTo(ms, prefix, maxAdditional: 1000);
        Assert.Equal(new byte[] { 1, 2, 3 }, result);
    }

    [Theory]
    [InlineData(-1, "Corrupted EXE: invalid MZ header.")]
    [InlineData(-2, "Corrupted MSI: invalid header.")]
    [InlineData(-3, "Invalid REG file format.")]
    [InlineData(-7, "Windows PE file detected, but not a recognized installer or archive.")]
    [InlineData(-6, "Unknown or unsupported file type.")]
    [InlineData(-99, "Unknown or unsupported file type.")]
    public void DescribeError_MapsCodesToMessages(int code, string expected) =>
        Assert.Equal(expected, InstallerDetector.DescribeError(code));

    private sealed class OneByteAtATimeStream : Stream
    {
        private readonly byte[] _data;
        private int _pos;
        public OneByteAtATimeStream(byte[] data) => _data = data;
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_pos >= _data.Length || count == 0) return 0;
            buffer[offset] = _data[_pos++];
            return 1;
        }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => _data.Length;
        public override long Position { get => _pos; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
