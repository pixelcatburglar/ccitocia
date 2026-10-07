# ccitocia

A native Rust desktop and command-line converter for **decrypted** Nintendo 3DS CCI (`.cci`
or `.3ds`) cartridge images. No makerom, Python, or other converter is required
at runtime. Generated CIAs have unsigned metadata and require custom firmware
with signature checks patched; they are not installable on stock firmware.

## Run

```powershell
cargo build --release
.\target\release\ccitocia-gui.exe
```

In the desktop window, choose an input file, optionally change the output path,
and click **Convert to CIA**. The window shows the current stage, progress,
bytes copied, elapsed time, and any error details. Conversion runs in the
background so the window stays responsive. Progress reaches 100% only after
the output is saved successfully. Errors can be copied with **Copy error details**.
Wait for conversion to finish before closing the window.

The command-line interface remains available:

```powershell
.\target\release\ccitocia.exe "D:\dumps\game.cci"
.\target\release\ccitocia.exe "D:\dumps\game.3ds" -o "D:\output\game.cia"
```

The default output is beside the input with a `.cia` extension. Existing files
are never overwritten. Conversion uses a temporary file in the output directory
and publishes the result only on success. Allow disk space for the selected
contents plus CIA metadata. Input files are opened read-only.

For a CLI-only build without desktop dependencies:

```powershell
cargo build --release --no-default-features --bin ccitocia
```

## Supported scope

- Decrypted NCCH partitions using 512-byte media units.
- Application, optional manual, and optional Download Play partitions (0–2).
  Update partitions are omitted.
- Application extended-header verification, SD application flag patching,
  replacement extended-header hash, CIA content hashes and TMD hash hierarchy.
- SMDH icon and dependency metadata; all ten ExeFS file entries are searched.
- Streaming content copying with a 1 MiB buffer and 64-bit sizes.

Encrypted images are rejected, including encrypted optional content. There is no
key import or decryption implementation. NAND dumps, malformed partition bounds,
overlapping partitions, unusual extended headers, and missing icons are rejected.
This is a packager, not a comprehensive NCCH integrity verifier: it checks the
application extended-header hash but does not verify every ExeFS/RomFS hash tree.
The ticket and TMD use unsigned retail templates with title version zero.

## Validation

```powershell
cargo test
cargo clippy --all-targets -- -D warnings
```

Synthetic tests check single/multiple/sparse content layouts, update omission,
ticket title IDs, content and metadata hashes, SD patching, source preservation,
existing-file protection, and invalid/encrypted inputs. **No real cartridge dump
or hardware installation has been tested.** Keep your original dumps.

Progress tests also cover multi-chunk byte counts, phase ordering, publication
failures, worker errors and reserving 100% for successful completion.

## Format references and attribution

The packaging layout and binary retail certificate/ticket/TMD templates are
based on [ihaveamac/3dsconv](https://github.com/ihaveamac/3dsconv), inspected at
commit `50a30d292e039a8b315eaccef85a067a8f48c500`. The templates are in `assets/`;
the upstream MIT notice is preserved in `assets/LICENSE-3dsconv.txt`.
They contain public certificates and unsigned metadata, not console private keys.

Format references: [CCI](https://www.3dbrew.org/wiki/CCI),
[CIA](https://www.3dbrew.org/wiki/CIA), and
[NCCH](https://www.3dbrew.org/wiki/NCCH).
