# Porting fidelity: AutoIt USSF → `ussfc`

This note records how faithfully the C# port reproduces
[alexandruavadanii/USSF](https://github.com/alexandruavadanii/USSF) (`ussf.au3`,
v1.4.1.2), what was intentionally left out, and where the two diverge. It is the
companion to the unit tests in [`tests/Ussf.Core.Tests`](../tests/Ussf.Core.Tests),
which pin the behavior described here.

## What was ported

The port reproduces the **file-type detection engine** — the part of USSF that
actually has lasting value:

- The `ParseProgram` dispatch (extension + header → message number).
- The `TestExeFile` PE classification (installer / SFX / packer identification).
- The full 16-entry message table (type name, silent-install usage, notes).
- The reg / inf / msi / exe header checks.

## What was intentionally **not** ported

The original is a Windows-only AutoIt GUI application. The following were dropped
on purpose because they do not belong in a cross-platform, headless CLI:

| Original feature | Status | Reason |
| ---------------- | ------ | ------ |
| WinForms-style GUI (`GUICreate`, labels, skins) | dropped | headless tool |
| Skins (`Black.skn`, `GetSkins`, `RedrawSkin`) | dropped | GUI only |
| Multi-language strings (`SetLanguage`, German, …) | English only | CLI emits one language |
| WPI integration (`AttachToWPI`, `SendToWPI`, registry `USSF_cmd*`) | dropped | Windows Post-Install-specific |
| Auto-update (`GetLatestVersionNumber`, `Update_Label`) | dropped | not a CLI concern |
| Registry reads/writes (`HKCU\Software\USSF`, `PEiD`) | dropped | no persisted settings |

The port also **adds** things the original lacked: `--json` output, stdin piping,
`--help` / `--version`, and cross-platform binaries.

## Detection mechanism: the key change

The original shells out to bundled Windows executables:

- **PEiD.exe** (`-hard`) returns a signature string that `TestExeFile` matches.
- **innounp.exe**, **unzip.exe**, **7z.exe** are run to confirm Inno / ZIP / 7-Zip.

None of those are portable, so the port replaces them with **case-sensitive byte
signature scanning of the PE content** plus a PE section-table check for UPX. The
mapping is:

| Original (PEiD / helper) | Port (byte signature) | Msg |
| ------------------------ | --------------------- | --- |
| `Nullsoft PiMP SFX` | `NullsoftInst` | 3 |
| `Inno Setup` / (Borland Delphi + innounp) | `Inno Setup` | 4 |
| `Installshield AFW` | — (see gap below) | 5 |
| `InstallShield 2003` | `InstallShield` / `Installshield` | 6 |
| `Wise Installer` / `PEncrypt 4.0` | `WiseMain` | 7 |
| `RAR SFX` | `52 61 72 21 1A 07` | 8 |
| `CAB SFX` / `SPx Method` | `4D 53 43 46 00 00 00 00` | 9 |
| `ZIP SFX` / (unzip signature found) | `50 4B 03 04` inside a PE | 10 |
| `Microsoft Visual C++` + 7z listing | `37 7A BC AF 27 1C` inside a PE | 11 |
| 7-Zip listing on a non-PE | `37 7A BC AF 27 1C` at offset 0 | 12 |
| unzip `Length` listing on a non-PE | `50 4B 03 04` at offset 0 | 13 |
| `WinZip` | `WinZip Self-Extractor` | 14 |
| `UPX` | `UPX0` / `UPX1` / `UPX2` section names | 15 |
| `.msi` OLE header | same OLE header | 16 |

Signature priority (first match wins) mirrors the original `Select`/`Case` order:
`3, 4, 6, 6, 7, 8, 9, 11, 14, 10`. UPX is checked before all of them.

## Known divergences

1. **Message 5 (Installshield AFW) is unreachable.** The original distinguished
   "Installshield AFW" (→ 5) from "InstallShield 2003" (→ 6) using PEiD's richer
   signatures. Byte scanning cannot cheaply tell them apart, so both collapse to 6.
   Message 5 is kept in the table for fidelity but no path returns it. Covered by
   `MessageTableTests.Message5_InstallshieldAfw_IsDefinedButUnreachable`.

2. **Reworded type names / notes.** The port polishes several strings, e.g.
   `Registry Data File` → `Registry file`, `Windows Installer File` → `MSI File`,
   `UPX Packed executable` → `UPX Packed`, and rewrites the "unpack" notes. The
   exact current strings are pinned in `MessageTableTests`.

3. **A few usage lines differ from the original's `N/A`.** `SetNA()` in the
   original blanked the usage for messages 10 (ZIP SFX), 11 (7-Zip installer) and
   14 (WinZip SFX); the port instead emits `"{filename}" /s` for those. This is a
   deliberate usability choice, not a detection change.

4. **Lost packer aliases.** The `PEncrypt 4.0` (Wise), `SPx Method` (CAB) and the
   `Borland Delphi → innounp/unzip` fallback branches are not reproduced. Modern
   Inno/Wise/CAB binaries are still caught by their primary signatures, but exotic
   older stubs that only PEiD could name may fall through to "unrecognized PE".

5. **Reg validation is slightly more lenient.** The original compares the exact
   hex of `…Version 5.00\r\n` / `REGEDIT4\r\n`; the port uses a `StartsWith` check
   (no required trailing CRLF) with UTF-8 and UTF-16LE handling.

6. **Extra heuristics added.** For extension-less/stdin input the port adds an
   INF-like `[section]` heuristic and treats a bare 7-Zip/ZIP magic at offset 0 as
   a raw archive (12/13). The original was always extension-driven.

## Error-code mapping

The original's negative codes (`-1`..`-8`) are collapsed to the set the CLI
surfaces: `-1` corrupt EXE, `-2` corrupt MSI, `-3` invalid REG, `-6` unsupported,
`-7` valid-PE-but-unrecognized (covers the original `-5`/`-8`). See
`InstallerDetector.DescribeError` and `HelperTests.DescribeError_MapsCodesToMessages`.

## Test coverage

`dotnet test tests/Ussf.Core.Tests` runs 113 tests covering: every shallow-detection
branch, every EXE signature and its priority ordering, UPX section detection, the
4 MB chunk-boundary carry-over in the stream scanner, stream/buffer parity, the full
message table, the header/reg/inf helpers, stream draining, and the error mapping.
