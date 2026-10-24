# Install the prebuilt CLI

This archive contains the universal macOS command-line binary and example configuration.
It does not require Rust or Xcode. Verify the archive's published SHA-256 before extracting it.

From the extracted `cg-researcher` directory:

```sh
./cg-researcher --version
mkdir -p "$HOME/.local/bin"
install -m 0755 ./cg-researcher "$HOME/.local/bin/cg-researcher"
"$HOME/.local/bin/cg-researcher" init
```

Add `$HOME/.local/bin` to your shell's `PATH` if needed. The CLI's `init` command creates
the default data home at `~/.cg-researcher`; it preserves existing configuration and keys.
Use `--home /path/to/data` before `init` to select another home.

Run a local model server, then start `cg-researcher serve`. In a second terminal, run
`cg-researcher ui` to open and pair the web UI. See `README.md` for configuration and use.

The binary is ad-hoc signed, not Developer ID signed or notarized. Downloaded archives may
be quarantined by Gatekeeper; a successful checksum does not establish Apple notarization.

For the launchd service, scheduled maintenance, or optional Net-Viewer installation,
clone the source repository and follow its `scripts/install.sh` instructions. The source
installer is not included here because it requires the Cargo manifest and source tree.

To uninstall this manual CLI installation, remove only the binary you installed at
`$HOME/.local/bin/cg-researcher`. Keep your data home unless you intend to remove its
configuration, corpus and keys. This manual installation creates no launchd jobs.
