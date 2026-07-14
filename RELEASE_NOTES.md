# Release Notes - ReconTool v1.1.0

## New Features & Improvements

### Production-Quality Automated Asset Validation
- Implemented in-memory diagnostic checks for compiled executable binary headers:
  - **Linux**: Validates ELF header machine type (EM_X86_64, EM_AARCH64).
  - **Windows**: Validates PE header machine type (AMD64, ARM64).
  - **macOS**: Validates Mach-O header CPU type (AMD64, ARM64).
- Added archive entry checks verifying that zip packages contain only the expected binary file with correct permissions.
- Added Debian package structure validations verifying members (`debian-binary`, `control.tar.gz`, `data.tar.gz`).
- Any build validation error aborts the release pipeline immediately.

### Standardized Release Artifacts
- **Packaging Format**: Releases are distributed in standardized `.zip` (with `chmod +x` executable permissions on Unix targets) and `.deb` Debian package formats.
- **Source Code Archive**: Included a gzipped source code tarball `recontool_1.1.0_source.tar.gz` containing only necessary Go sources and metadata, excluding build directories.
- **Checksum Verification**: Re-aligned `recontool_1.1.0_checksums.txt` formatting to match standard `<hash>  <filename>` specifications, providing direct compatibility with `sha256sum -c`.
