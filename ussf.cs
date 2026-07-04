#!/usr/bin/env dotnet

#:project src/Ussf.Core/Ussf.Core.csproj

#:property Version=1.4.1.2-preview.1
#:property AssemblyVersion=1.4.1.2
#:property FileVersion=1.4.1.2
#:property InformationalVersion=1.4.1.2-preview.1

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

using System.Text.Json;
using Ussf.Core;

const string Version = "1.4.1.2-preview.1";

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
int messageNumber;

if (stdinMode)
{
    displayName = "<stdin>";
    extension = null;
    using var stdin = Console.OpenStandardInput();
    var headerBuffer = InstallerDetector.ReadHeaderBytes(stdin, InstallerDetector.HeaderLength);
    messageNumber = InstallerDetector.DetectFromBytes(headerBuffer, extension);
    if (messageNumber == InstallerDetector.ExeNeedsDeepScan)
    {
        var fullData = InstallerDetector.AppendStreamUpTo(stdin, headerBuffer, InstallerDetector.MaxStdinDeepScanBytes);
        messageNumber = InstallerDetector.DetectExeKindFromBuffer(fullData);
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
    messageNumber = InstallerDetector.DetectFromStream(fs, extension);
}

if (messageNumber > 0 && InstallerDetector.Messages.ContainsKey(messageNumber))
{
    var msg = InstallerDetector.Messages[messageNumber];
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
    string errorMsg = InstallerDetector.DescribeError(messageNumber);

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
