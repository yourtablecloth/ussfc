# USSF-CSharp (`ussfc`)

**Universal Silent Setup Finder / Console** — a C# port of [alexandruavadanii/USSF](https://github.com/alexandruavadanii/USSF), reimagined as a cross-platform, headless command-line tool.

Given an installer (or any binary stream), `ussfc` identifies the packaging format and prints the silent-install command line to use.

- **Version:** 1.4.1.2 (inherited from the upstream AutoIt project)
- **Runtime:** .NET 10 file-based app (single `.cs` source, no `.csproj`)
- **License:** Apache-2.0

---

## Installation

### Download a prebuilt binary

Grab the archive for your platform from the [Releases](../../releases) page:

| Platform           | Archive                       |
| ------------------ | ----------------------------- |
| Windows x64        | `ussfc-win-x64.zip`           |
| Windows ARM64      | `ussfc-win-arm64.zip`         |
| Linux x64          | `ussfc-linux-x64.tar.gz`      |
| Linux ARM64        | `ussfc-linux-arm64.tar.gz`    |
| macOS x64 (Intel)  | `ussfc-osx-x64.tar.gz`        |
| macOS ARM64 (M1+)  | `ussfc-osx-arm64.tar.gz`      |

Each archive contains a single self-contained `ussfc` (or `ussfc.exe`) binary — no .NET runtime install required.

### Run from source (.NET 10 SDK required)

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

Where `<rid>` is one of: `win-x64`, `win-arm64`, `linux-x64`, `linux-arm64`, `osx-x64`, `osx-arm64`.

### Continuous delivery

Pushing a tag matching `v*` (e.g. `v1.4.1.2`) triggers [`.github/workflows/release.yml`](.github/workflows/release.yml), which builds binaries for all six target platforms, bundles them with `README.md` / `LICENSE`, generates SHA-256 checksums, and publishes a GitHub Release.

The workflow is also runnable on demand via the **Run workflow** button (workflow_dispatch).

---

## Credits

- Original AutoIt implementation: **[Alexandru Avadanii](https://github.com/alexandruavadanii/USSF)** (Apache-2.0).
- C# port and CLI design: **Jung-Hyun Nam**.

The version number `1.4.1.2` is preserved from the upstream project's [`Version.au3`](https://github.com/alexandruavadanii/USSF/blob/master/Version.au3) to make the lineage explicit.
