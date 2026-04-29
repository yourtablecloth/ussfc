# USSF-CSharp (`ussfc`)

[![NuGet](https://img.shields.io/nuget/v/ussfc.svg?logo=nuget)](https://www.nuget.org/packages/ussfc)
[![NuGet Downloads](https://img.shields.io/nuget/dt/ussfc.svg)](https://www.nuget.org/packages/ussfc)
[![Release](https://github.com/yourtablecloth/ussfc/actions/workflows/release.yml/badge.svg)](https://github.com/yourtablecloth/ussfc/actions/workflows/release.yml)

**Universal Silent Setup Finder / Console** — a C# port of [alexandruavadanii/USSF](https://github.com/alexandruavadanii/USSF), reimagined as a cross-platform, headless command-line tool.

Given an installer (or any binary stream), `ussfc` identifies the packaging format and prints the silent-install command line to use.

- **Version:** 1.4.1.2 (inherited from the upstream AutoIt project)
- **Runtime:** .NET 10 file-based app (single `.cs` source, no `.csproj`)
- **License:** Apache-2.0

---

## Installation

Pick the option that fits your workflow.

### Option 1 — Run with `dnx` (no install, .NET 10 SDK)

The fastest way to try `ussfc`. `dnx` is a one-shot tool runner shipped with the .NET 10 SDK; the first invocation downloads the package to your NuGet cache, subsequent runs are instant.

```bash
dnx ussfc setup.exe
```

If `dnx` isn't on your PATH, the equivalent works in any .NET 10 environment:

```bash
dotnet tool exec ussfc -- setup.exe
```

### Option 2 — Install as a .NET global tool (.NET 10 SDK)

For repeated use, install once and call `ussfc` directly from any directory:

```bash
dotnet tool install -g ussfc
ussfc setup.exe
```

Update with `dotnet tool update -g ussfc`, remove with `dotnet tool uninstall -g ussfc`.

### Option 3 — Download a prebuilt self-contained binary (no .NET required)

Grab the archive for your platform from the [Releases](../../releases) page:

| Platform           | Archive                       |
| ------------------ | ----------------------------- |
| Windows x64        | `ussfc-win-x64.zip`           |
| Windows ARM64      | `ussfc-win-arm64.zip`         |
| Linux x64          | `ussfc-linux-x64.tar.gz`      |
| Linux ARM64        | `ussfc-linux-arm64.tar.gz`    |
| macOS ARM64 (M1+)  | `ussfc-osx-arm64.tar.gz`      |

Each archive contains a single NativeAOT-compiled `ussfc` (or `ussfc.exe`) binary — no .NET runtime install required.

### Option 4 — Run directly from source (.NET 10 SDK)

```bash
dotnet run ussf.cs -- setup.exe
```

Or, with the shebang on Unix:

```bash
chmod +x ussf.cs
./ussf.cs setup.exe
```

---

## Usage

```text
ussfc [options] <file_path>
<data> | ussfc [options]
```

### Options

| Option           | Description                                                  |
| ---------------- | ------------------------------------------------------------ |
| `--json`         | Emit the result as JSON instead of human-readable text.      |
| `--help`, `-h`   | Show usage information.                                      |
| `--version`, `-v`| Print the version and exit.                                  |

### Examples

Analyze a file:

```bash
ussfc setup.exe
```

```text
File: setup.exe
Extension: .exe
Type: NSIS Package
Usage: "setup.exe" /S
```

Emit JSON:

```bash
ussfc --json setup.msi
```

```json
{
  "file": "setup.msi",
  "extension": ".msi",
  "type": "MSI File",
  "usage": "msiexec.exe /i \"setup.msi\" /qb",
  "notes": ""
}
```

Pipe a binary from stdin:

```bash
cat setup.exe | ussfc --json
```

---

## Supported file types

| Extension | Type                                                                       |
| --------- | -------------------------------------------------------------------------- |
| `.inf`    | Information / Installation file                                            |
| `.reg`    | Registry file                                                              |
| `.msi`    | Windows Installer package                                                  |
| `.exe`    | NSIS, Inno Setup, InstallShield, Wise, 7-Zip, WinZip, UPX, and more         |

Detection combines binary-signature matching (MZ, OLE Compound Document, etc.) with extension and text-content fallbacks.

---

## Building from source

### Quick run

```bash
dotnet run ussf.cs -- <args>
```

### Publish a single-file binary

```bash
dotnet publish ussf.cs \
  -c Release \
  -r <rid> \
  --self-contained true \
  -p:PublishSingleFile=true \
  -o publish
```

Where `<rid>` is one of: `win-x64`, `win-arm64`, `linux-x64`, `linux-arm64`, `osx-arm64`.

### Pack as a .NET tool

```bash
dotnet pack ussf.cs -c Release -o nupkg
```

The resulting `ussfc.<version>.nupkg` is a framework-dependent, platform-agnostic .NET tool package (`tools/net10.0/any/`) that targets net10.0.

### Continuous delivery

Pushing a tag matching `v*` (e.g. `v1.4.1.2`) triggers [`.github/workflows/release.yml`](.github/workflows/release.yml), which:

1. Builds NativeAOT single-file binaries for five RIDs and bundles them with `README.md` / `LICENSE`.
2. Packs `ussf.cs` as a .NET tool NuGet package and pushes it to nuget.org (requires the `NUGET_API_KEY` repository secret).
3. Publishes a GitHub Release with all binary archives, SHA-256 checksums, and the `.nupkg`.

The workflow is also runnable on demand via the **Run workflow** button (workflow_dispatch).

---

## Credits

- Original AutoIt implementation: **[Alexandru Avadanii](https://github.com/alexandruavadanii/USSF)** (Apache-2.0).
- C# port and CLI design: **Jung-Hyun Nam**.

The version number `1.4.1.2` is preserved from the upstream project's [`Version.au3`](https://github.com/alexandruavadanii/USSF/blob/master/Version.au3) to make the lineage explicit.
