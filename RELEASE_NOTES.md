# Release Notes - ReconTool v1.0.9

## New Features & Improvements

### Robust Domain Normalization & Chaos Matching
- Replaced custom split-based domain parsing with standard, secure public suffix analysis using `golang.org/x/net/publicsuffix`.
- Target domains are normalized case-insensitively and parsed to extract the registerable base domain (e.g., `example.com` -> `example`, `sub.example.co.uk` -> `example`).
- Subdomains and multiple TLD parts are correctly stripped without affecting the base domain part.

### Resilient Pipeline Execution
- Wayback CDX and ProjectDiscovery Chaos lookup stages now execute completely independently.
- HTTP 429 (Too Many Requests) errors and other network failures in one stage do not affect or terminate subsequent stages.
- Output files are consistently created as empty files on query failure to guarantee directory structure predictability.

### Safe ZIP Extraction & Merge
- The Chaos dataset downloader now extracts `.txt` lists by merging them with any existing subdomains, removing duplicates, and writing them safely without overwriting or corrupting prior data.

### Concise Standardized Logging
- Console output has been cleaned up. Diagnostic messages now follow a strict prefix format:
  - `[STEP]` for pipeline phases.
  - `[SUCCESS]` for successful completions.
  - `[INFO]` for informational logs.
  - `[WARNING]` for handled non-fatal errors (e.g., HTTP 429).
  - `[ERR]` for fatal errors.

### Release Artifacts & Naming
- Added automated cross-compilation pipeline script producing standard naming format:
  `recontool_<version>_<os>_<architecture>.zip`
- Includes SHA256 checksum file:
  `recontool_<version>_checksums.txt`
