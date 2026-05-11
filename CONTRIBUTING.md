# Contributing

Thanks for taking the time. The project is small but the knowledge base
behind it is the main thing that grows with help from people running
SentinelOne against products the maintainer doesn't have hands-on access
to. Most useful contributions fall into one of three buckets, ranked
roughly by how often they're needed.

## 1. Add a product to the knowledge base

This is the highest-leverage contribution. If you operate a product not
already in the KB and you know which paths, processes, and file
extensions cause noise under SentinelOne, please open a PR.

**Windows products** live near the top of `S1-ExclusionGenerator.ps1`
inside the `$TelcoKB` array. Copy any existing entry as a template:

```powershell
@{ Name="Your Product"; Category="Database"; Risk="High";
   Paths=@(
       "C:\Program Files\Your Product\",
       "%YOUR_HOME%\data\"
   )
   Processes=@("yourproduct.exe", "ypsvc*.exe")
   Extensions=@("ydb", "ylog")
   Notes="One-line rationale: what the product does and why these exclusions are safe."
},
```

**Linux products** live in `s1_discovery.sh` as detector functions of the
shape:

```bash
# ── Your Product ─────────────────────────────────────────────────────────────────
if is_running yourproductd || svc_on yourproduct; then
    found "Your Product"
    add_proc "yourproductd"
    add_path "/var/lib/yourproduct"
    add_path "/var/log/yourproduct"
    add_ext  ".ydb"
fi
```

A few things to think about before you send the PR:

- **Be conservative with extension exclusions.** An extension like
  `exe`, `dll`, `so`, `bin`, or anything that matches user-writable
  binaries should never appear. Stick to data files that the product
  writes constantly (`.dbf`, `.ibd`, `.wt`, `.vbk`, ...).
- **Prefer named paths over `/`-rooted globs.** Wide path exclusions
  like `/var/lib/*` blind the agent to too much.
- **Pick a Risk level honestly.** `Critical` should be reserved for
  products that genuinely fall over without the exclusion (databases,
  billing engines, AD). `Low` is the right default for "nice to have".
- **Notes matter.** A reviewer two years from now needs to understand
  why this entry exists. One sentence is enough.

## 2. Improve the matching engine

The PowerShell matcher in `Find-ExclusionMatches` runs each KB entry
against installed software, running processes, and running services
along four axes. Bug reports against false positives or missed matches
are welcome, especially with the offending KB row and a short repro.

The Linux discoverer in `s1_discovery.sh` uses per-product detector
functions instead of a single matcher. Edge cases (non-standard
install paths, distros that name a service differently) should be
fixed in the detector itself, not in a global override.

## 3. Documentation / packaging

README, CHANGELOG, examples, packaging for other deployment systems
(SCCM application, Ansible role, etc.) -- all welcome.

## House rules

- One concern per pull request. A KB addition for Oracle plus a
  README fix is two PRs, not one.
- Keep commit messages descriptive (`feat: add Oracle Goldengate to KB`,
  not `update`).
- The CI workflow runs `PSScriptAnalyzer` and `shellcheck` on every
  push and PR. Green CI is required before merge.
- The `main` branch is protected: force-pushes and deletions are
  blocked, all commits must be signed, and history must stay linear.
  Squash-merge or rebase-merge your PR -- merge commits will be
  rejected.
- New external dependencies require a strong justification. Both
  scripts deliberately depend on nothing outside what ships with the
  target OS (stock PowerShell on Windows, stock bash + coreutils on
  Linux). Keep it that way unless there's a compelling reason.

## Questions

If you're not sure your idea is a fit, open an issue first and ask. Low
overhead, faster than building something nobody wants.
