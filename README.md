# S1-ExclusionGenerator

A SentinelOne exclusion-recommendation generator for Windows endpoints.

The script inventories a Windows host (installed software, running services,
running processes) and matches what it finds against a curated knowledge
base of enterprise, Telco, Mobile Money, and fintech products. The output
is a SentinelOne-ready exclusion list in four formats — HTML, CSV, JSON,
and TXT — that an analyst can review and import into the S1 management
console.

The intent is to make onboarding new Windows endpoints to SentinelOne
faster and less error-prone, particularly on database, middleware, and
billing hosts where missing antivirus exclusions are a frequent cause of
performance regressions.

## Author

Alaa G. Sukarieh

## Quick start

Run the script in an **elevated** PowerShell session on the host you
want to inventory:

```powershell
.\S1-ExclusionGenerator.ps1
```

Reports are written next to the script. Open the `.html` file for the
interactive report.

To write the reports somewhere else:

```powershell
.\S1-ExclusionGenerator.ps1 -OutputPath C:\Reports\S1
```

## Requirements

| Component        | Supported                                       |
|------------------|-------------------------------------------------|
| PowerShell       | 5.1 and up (the default shell on every modern Windows release) |
| Windows client   | Windows 7 SP1 through Windows 11                |
| Windows Server   | Windows Server 2008 R2 SP1 through Windows Server 2025 |
| Privileges       | Local Administrator (script warns and continues otherwise) |
| Architecture     | x86 and x64                                     |

The script is local-execution only. It always inventories the machine it
runs on; the optional `-ComputerName` parameter is purely a display
label used in filenames and report headers.

## What it does

1. **Inventory.** Reads the standard `Uninstall` registry keys in HKLM
   (both native and `Wow6432Node`) and every loaded HKU user hive,
   filtering out OS components and hotfixes.

2. **Process and service enumeration.** Uses `Win32_Service` and
   `Win32_Process` (WMI) for accuracy. Falls back to `Get-Process` to
   recover the binary path for protected processes that WMI can't see.

3. **Matching.** Each KB entry is checked against the inventory along
   four axes:
   - installed-software display name (token-based, with a stop-word filter
     to avoid runaway false positives on generic words like "Server"),
   - running process name (wildcard-aware, so `tomcat*.exe` correctly
     matches `tomcat9.exe`),
   - service display name (token-based),
   - service binary path (catches services with generic display names
     whose `PathName` reveals the product).

4. **Unknown processes.** Anything running that does not live under
   `%SystemRoot%` and is not covered by any KB pattern is surfaced in a
   separate table so the analyst can decide whether additional
   exclusions are needed.

5. **Reports.** Four files per run:
   - `S1_Exclusions_<timestamp>_<host>.html` — interactive, filterable
   - `S1_Exclusions_<timestamp>_<host>.csv`  — import-ready
   - `S1_Exclusions_<timestamp>_<host>.json` — S1 API shape
   - `S1_Exclusions_<timestamp>_<host>.txt`  — plain summary

   Environment-variable tokens in KB exclusion paths (for example
   `%ORACLE_HOME%\bin\`) are resolved against the inventory host's
   environment before being written to the reports. Unresolved tokens
   are preserved and the operator is warned.

## Parameters

| Name          | Type     | Default              | Notes                              |
|---------------|----------|----------------------|------------------------------------|
| `OutputPath`  | string   | script directory     | Created if missing                 |
| `ComputerName`| string   | `$env:COMPUTERNAME`  | Display label only; not for remoting |

## Output structure

Each report contains, for every matched product:

- **Product / Match** — the KB product name and which inventory source
  triggered the match
- **Category** — Database, Middleware, Backup, SIEM, etc.
- **Risk** — Critical, High, Medium, Low
- **Exclude Paths** — directories the SentinelOne agent should ignore
  (environment variables already expanded)
- **Exclude Processes** — process names (wildcards preserved)
- **Extensions** — file extensions (dotted, ready to paste into the S1
  console)
- **Notes** — free-form rationale

## Exit codes

| Code | Meaning                                                  |
|------|----------------------------------------------------------|
| 0    | Clean run; reports written                               |
| 1    | Completed with one or more non-fatal export failures     |
| 2    | Could not create or access the output directory          |

This makes the script safe to schedule from RMM platforms, SCCM, Task
Scheduler, and similar.

## Knowledge base coverage

The built-in KB covers, among others:

- **Databases** — Oracle, Microsoft SQL Server, MySQL / MariaDB, PostgreSQL
- **Middleware / app servers** — Oracle WebLogic, JBoss / WildFly, Tomcat, WebSphere
- **Telco BSS / billing** — Oracle BRM, Ericsson BSCS, Comverse, Huawei CBS, Amdocs
- **Mobile Money / FinTech** — Oracle FLEXCUBE, Temenos T24, Pentaho BI
- **OSS / NMS** — Ericsson OSS / ENM, Nokia NetAct, Huawei iManager, SolarWinds, PRTG, Zabbix, Nagios
- **Web servers** — IIS, Apache, Nginx
- **Backup** — Veeam, Veritas NetBackup, Commvault, Windows Server Backup
- **Virtualisation** — VMware Tools, Hyper-V
- **Security co-existence** — Trend Micro, Symantec, McAfee / Trellix, Windows Defender
- **AAA / Messaging / VoIP** — Juniper SBR, NPS, CMG / Kannel, Metaswitch, AudioCodes
- **ERP** — SAP, Microsoft Dynamics 365 / AX
- **Remote access / VPN / RMM** — Citrix, Pulse Secure, FortiClient, GlobalProtect, Ivanti, ManageEngine, ConnectWise, TeamViewer, AnyDesk
- **SIEM agents** — Splunk, USM Anywhere, Elastic
- **Windows roles** — AD DS, WSUS, Exchange, Print Spooler

The KB lives at the top of the script. To extend it, copy any existing
`@{ Name = ... }` entry and edit in place — no other code change is
needed.

## Safety notes

- **This is a recommendation tool, not a configuration tool.** It never
  contacts the SentinelOne API and never modifies the agent. Always
  review the generated lists before importing them.
- **Apply exclusions at the policy level, not globally.** A global
  exclusion in the S1 console weakens every endpoint in the tenant.
- **Validate against vendor guidance.** SentinelOne publishes
  product-specific exclusion guides; the KB here is a starting point,
  not a substitute.
- **Run elevated.** Without administrator rights, process paths for
  other security contexts and parts of the HKU registry hive are
  inaccessible, and the inventory is incomplete. The script warns when
  this is the case.

## Versioning

| Version | Notes                                                 |
|---------|-------------------------------------------------------|
| 2.2     | Hardened release: strict mode, error handling, wildcard-aware unknown-process filter, working registry walk (HKLM PSDrive + per-SID HKU enumeration), env-var expansion, sanitised filenames, useful exit codes, elevation warning, console-encoding fix |
| 2.1     | Initial public version                                |

## License

[MIT](LICENSE) — see the LICENSE file for the full text.

## Contributing

Issues and pull requests are welcome. The KB is the part most likely to
need community input; if you operate a product not in the list, a short
PR adding it (with a sensible `Risk` rating and `Notes`) is the best
contribution.
