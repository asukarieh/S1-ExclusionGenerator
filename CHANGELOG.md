# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.3] - 2026-05-11

### Added
- **`s1_discovery.sh`** — Linux companion to the PowerShell generator
  (v1.0, MIT). Detects running services and produces a SentinelOne-ready
  exclusion list (paths, processes, file extensions) at
  `/tmp/s1_exclusions_<hostname>_<timestamp>.txt` by default.
  - Coverage: Apache, Nginx, PHP-FPM, Tomcat / Java app servers, MySQL /
    MariaDB, PostgreSQL, Oracle Database (with auto-discovery of each
    running SID's datafile / redo / control / dump directories via
    `sqlplus / as sysdba`), Oracle ASM, MongoDB, Redis, Elasticsearch,
    Cassandra, RabbitMQ, HAProxy, Docker, Kubernetes, NFS server,
    auto-discovered remote NFS / CIFS mounts, Veeam Agent, Commvault,
    Bacula.
  - Resolves authoritative data paths from live process arguments first
    (`/proc/<pid>/environ`, `ps -ef`, `pg_lsclusters`, `my_print_defaults`),
    then falls back to common defaults.
  - `--help` flag prints the embedded usage block; `-o <path>` lets the
    operator redirect the output anywhere.
  - Hostname is sanitised (matches the PowerShell side) so weird DNS
    names never break the output filename.
  - Refuses to run as a non-root user; some inventory steps need root.

### Changed
- Universal `/tmp` and `/var/tmp` exclusions in the Linux script are now
  annotated with a security warning in the WARNINGS section of the
  generated report. Operators are explicitly prompted to consider removing
  them before importing, since `/tmp` is a common malware-drop location
  and excluding it blinds the EDR to a large class of attacker behaviour.

## [2.2] - 2026-05-11

### Fixed
- **Registry walk was returning zero installed-software entries.** The
  previous code used an invalid `Registry::HKLM:\...` provider path
  (hybrid of provider-qualified and PSDrive syntax). Switched to the
  `HKLM:` PSDrive form and added a dynamically-registered `HKU:` drive
  that iterates per-SID Uninstall subkeys correctly.
- **`$Matches` variable collision.** Renamed the local accumulator and
  every export-function parameter so they no longer shadow PowerShell's
  automatic `$Matches` regex variable. A `-match` operator firing in
  the matching loop no longer clobbers the result array.
- **Unknown-process filter was raising false positives.** `-notcontains`
  performs exact equality, not wildcard matching. Replaced with a
  wildcard-aware helper (`Test-MatchesAnyPattern`) so KB entries like
  `tomcat*.exe` correctly cover a real `tomcat9.exe`.
- **Hard-coded `C:\Windows` path in the system-folder filter.** Now
  uses `[Environment]::GetFolderPath('Windows')` so hosts installed on
  a non-C: drive are handled correctly.
- **Tuple-return destructuring was fragile.** `Find-ExclusionMatches`
  now returns a named hashtable instead of `return $a, $b`. The main
  loop accesses fields by name; behaviour is now identical for empty,
  single-element, and multi-element results.

### Added
- `Set-StrictMode -Version 3.0` and `$ErrorActionPreference = 'Stop'`
  at script entry. Hidden bugs (null-property dereferences, uninitialised
  variables) now surface immediately instead of silently producing
  wrong reports.
- Elevation check at startup that warns when the script is not running
  as Administrator (inventory will be partial without it).
- Output-directory validation and resolution up front. The script exits
  early with a clear message if it cannot write to the requested folder
  instead of crashing inside an `Export-*` call later.
- `Test-IsAdmin`, `ConvertTo-SafeFileName`, `Expand-ExclusionPath`,
  `Test-MatchesAnyPattern`, and `Get-ProductTokens` helper functions.
- Environment-variable expansion for KB exclusion paths
  (`%ORACLE_HOME%`, `%systemroot%`, ...). Unresolved tokens are kept
  raw and surface a warning so a human can act on them.
- Service-binary-path matching as a fourth match axis. Catches
  services with generic `DisplayName` (e.g. an app named "AppSvc"
  whose `PathName` is `C:\Tomcat9\bin\tomcat9.exe`).
- `Get-Process` fallback for `Win32_Process.ExecutablePath` when WMI
  cannot read the path of protected / PPL processes.
- HKLM uninstall enumeration now filters out `SystemComponent`,
  `ParentKeyName`, and `ReleaseType in {Update, Hotfix, Security
  Update}` so OS internals do not pollute the inventory.
- Exit codes: `0` clean, `1` completion with non-fatal failures,
  `2` cannot access output directory. Makes the script safe to
  schedule from RMM / Task Scheduler / SCCM.
- Hostname sanitisation (`ConvertTo-SafeFileName`) before use in
  filenames, so values like `DOMAIN\HOST` no longer crash file writes.
- `Write-Warn` and `Write-Fail` helpers that emit to both the host and
  the warning stream, so warnings are now captured by transcripts and
  `3>&1` redirection.
- `CHANGELOG.md`, `README.md`, `LICENSE`, and `.gitignore` so the
  project is presentable as an open-source repository.

### Changed
- **Required PowerShell version bumped to 5.1** (was a stale
  `#Requires -Version 2.0` that did not match the features the script
  used).
- **Matching tokeniser rewritten.** The previous `-split " "` produced
  tokens like `(all` and `versions)` and over-broad single words like
  `Server`. New tokeniser strips punctuation and filters a stop-word
  list, dramatically reducing both false positives and missed matches.
- **Export functions renamed** from `Export-CSV/JSON/TXT/HTML` to
  `Export-ExclusionCSV/JSON/TXT/HTML` so they no longer shadow the
  built-in `Export-Csv` cmdlet.
- **TXT and JSON outputs now prepend a dot** to extension entries,
  matching the CSV and HTML output for consistency with S1 console
  conventions.
- **JSON depth bumped** from 5 to 10 for defensive headroom.
- **Console banner switched to ASCII**, replacing the box-drawing and
  check-mark Unicode characters that rendered as `?` on legacy
  Windows consoles (Server 2008 R2 / 2012 / 2016 `conhost.exe` raster
  fonts).
- **HTML report rebranded** with the author's name; removed third-party
  customer and consultancy references from titles, footers, and KB
  notes.
- Ivanti KB entry: removed `exe` and `msi` from the extension list
  (would have whitelisted every executable on disk).

### Removed
- Unused `$ScanMode` and `$ExclusionType` parameters that were
  documented but never honoured by the script body.
- Remote-execution code paths and the `-ComputerName` array parameter.
  The script is now strictly local-execution; `-ComputerName` survives
  as a single-string display label only.

## [2.1] - 2026-05-06

- Initial public version.
