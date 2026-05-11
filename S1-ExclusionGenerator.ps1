#Requires -Version 5.1
<#
.SYNOPSIS
    SentinelOne Exclusion Generator for Windows endpoints.

.DESCRIPTION
    Inventories installed software (registry), running services (WMI), and
    active processes (WMI) on the local Windows host, then matches findings
    against a curated knowledge base of enterprise, Telco, Mobile Money, and
    fintech products. Produces SentinelOne-ready exclusion recommendations
    in four formats:

      - HTML   interactive, filterable report
      - CSV    import-ready for the SentinelOne management console
      - JSON   machine-readable (S1 API shape)
      - TXT    plain-text summary

    The intent is to help engineers onboard new Windows endpoints to
    SentinelOne quickly without missing the antivirus exclusions that
    typically cause performance regressions on database, middleware, and
    billing hosts.

.PARAMETER OutputPath
    Directory where reports are written. Created if it does not exist.
    Defaults to the script's own folder; falls back to the current working
    directory when the script is dot-sourced and $PSScriptRoot is null.

.PARAMETER ComputerName
    Hostname used to label the reports. Defaults to the local machine name.
    The script always inventories the local host; this parameter is purely
    a display value used in filenames and report headers.

.NOTES
    Author  : Alaa G. Sukarieh
    Version : 2.2
    License : MIT
    Tested  : Windows PowerShell 5.1 on Windows 7 SP1 through Windows 11
              and Windows Server 2008 R2 SP1 through Windows Server 2025.
    Run As  : Local Administrator. The script will warn and continue when
              it detects a non-elevated session, but inventory will be
              incomplete (process paths for other security contexts and
              parts of the HKU registry hive will be inaccessible).

.EXAMPLE
    # Default run -- generate reports in the script folder
    .\S1-ExclusionGenerator.ps1

.EXAMPLE
    # Write reports to a specific folder
    .\S1-ExclusionGenerator.ps1 -OutputPath C:\Reports\S1
#>

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = $PSScriptRoot,

    [ValidateNotNullOrEmpty()]
    [string]$ComputerName = $env:COMPUTERNAME
)

# ============================================================
#  STRICT MODE / ERROR POLICY
# ============================================================
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# Best-effort: try to make the console render the box-drawing characters
# and check marks used below. Older consoles may not honour this; the
# script keeps working either way.
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding            = [System.Text.Encoding]::UTF8
} catch { }

# Track non-fatal failures so the script can return a useful exit code
# to automation callers (Task Scheduler, RMM, SCCM, etc.).
$script:Failures = 0

# ============================================================
#  CONFIGURATION
# ============================================================
$ScriptVersion  = '2.2'
$ScriptAuthor   = 'Alaa G. Sukarieh'
$ReportDate     = Get-Date -Format 'yyyy-MM-dd_HH-mm'
$ReportBaseName = "S1_Exclusions_$ReportDate"

# Resolve OutputPath when $PSScriptRoot is null (ISE selection, dot-source,
# Get-Content | Invoke-Expression, etc.).
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = (Get-Location).Path
}

# Create / validate the output directory up front so we fail fast with a
# useful message instead of crashing inside an Export-* call later.
try {
    if (-not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop | Out-Null
    }
    $OutputPath = (Resolve-Path -LiteralPath $OutputPath).ProviderPath
} catch {
    Write-Error "Cannot create or access output directory '$OutputPath': $($_.Exception.Message)"
    exit 2
}

# ============================================================
#  CONSOLE OUTPUT HELPERS
# ============================================================
function Write-Header  { param($msg) Write-Host "`n[*] $msg" -ForegroundColor Cyan }
function Write-Success { param($msg) Write-Host "  [+] $msg" -ForegroundColor Green }
function Write-Info    { param($msg) Write-Host "      $msg" -ForegroundColor Gray }

# Emits to host (visible) AND the warning stream (capturable by transcript
# or 3>&1 redirection). Replaces the v2.1 Write-Warning2 helper.
function Write-Warn {
    param($msg)
    Write-Host "  [!] $msg" -ForegroundColor Yellow
    Write-Warning $msg -WarningAction Continue
}

# Marks a non-fatal failure: visible in console, captured by the warning
# stream, and bumps $script:Failures so the final exit code reflects it.
function Write-Fail {
    param($msg)
    Write-Host "  [X] $msg" -ForegroundColor Red
    Write-Warning $msg -WarningAction Continue
    $script:Failures++
}

# Backwards-compatibility shim for callers / pipelines that used the v2.1
# helper name.
function Write-Warning2 { param($msg) Write-Warn $msg }

# ============================================================
#  UTILITY HELPERS
# ============================================================

# Returns $true when the current PowerShell process is running with
# Administrator rights. Used to warn the operator that inventory will be
# partial when not elevated.
function Test-IsAdmin {
    try {
        $current   = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($current)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

# Replaces characters that are illegal in Windows filenames so the report
# files can always be written regardless of how the host was named
# (DOMAIN\HOST, IPv6 literal, FQDN with reserved chars, etc.).
function ConvertTo-SafeFileName {
    param([Parameter(Mandatory)][string]$Name)
    $invalid = [System.IO.Path]::GetInvalidFileNameChars() -join ''
    $pattern = '[{0}]' -f [Regex]::Escape($invalid)
    $clean   = ($Name -replace $pattern, '_').Trim('.', ' ')
    if ([string]::IsNullOrWhiteSpace($clean)) { 'UNKNOWN' } else { $clean }
}

# Expands %VAR% style environment variables embedded in KB exclusion paths.
# SentinelOne does not expand %VAR% tokens at agent runtime, so the script
# resolves them on the inventory host. When the variable is undefined the
# raw string is preserved so a human reviewer can decide what to do.
function Expand-ExclusionPath {
    param([Parameter(Mandatory)][string]$Path)
    if ($Path -notmatch '%[^%]+%') { return $Path }
    $expanded = [Environment]::ExpandEnvironmentVariables($Path)
    if ($expanded -match '%[^%]+%') {
        Write-Warn "Unresolved environment variable in exclusion path: $Path"
        return $Path
    }
    return $expanded
}

# Wildcard-aware membership test. PowerShell's -contains / -notcontains
# operators do exact equality only -- they treat 'tomcat*.exe' as a
# literal string and never match a real process named 'tomcat9.exe'.
# This helper performs the wildcard match the KB entries are written for.
function Test-MatchesAnyPattern {
    param(
        [string]$Value,
        [string[]]$Patterns
    )
    if ([string]::IsNullOrEmpty($Value) -or -not $Patterns) { return $false }
    foreach ($p in $Patterns) {
        if (-not [string]::IsNullOrEmpty($p) -and ($Value -like $p)) { return $true }
    }
    return $false
}

# Generic stop-words that, on their own, would cause runaway false-positive
# matches against installed software / service names. These are filtered
# out of the token list produced by Get-ProductTokens.
$script:NameStopWords = @(
    'Server','Service','Services','System','Network','Software','Agent',
    'Client','Manager','Module','Console','Solution','Windows','Microsoft',
    'Oracle','Database','Application','Platform','Component'
)

# Splits a KB product name into matching tokens. Strips punctuation
# (parentheses, slashes, ampersands, etc.), drops short tokens, and
# removes the stop-words above. Returns an empty array for null input.
function Get-ProductTokens {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return @() }
    $tokens = $Name -split '[^A-Za-z0-9]+' |
              Where-Object {
                  $_.Length -gt 4 -and
                  $script:NameStopWords -notcontains $_
              }
    return @($tokens)
}

# ============================================================
#  TELCO / ENTERPRISE KNOWLEDGE BASE
#
#  Each entry is a hashtable with:
#    Name        - human-readable product name (used for matching tokens)
#    Category    - high-level grouping (Database, Middleware, Backup, ...)
#    Risk        - Critical | High | Medium | Low
#    Paths       - directories to exclude (supports %VAR% env tokens)
#    Processes   - process names to exclude (supports * wildcards)
#    Extensions  - file extensions to exclude (no leading dot; added at
#                  export time so the four output formats stay consistent)
#    Notes       - free-form rationale
# ============================================================
$TelcoKB = @(

    # ---- DATABASES ----
    @{ Name="Oracle Database (all versions)"; Category="Database"; Risk="Critical";
       Paths=@(
           "C:\oracle\*",
           "C:\app\*\product\*\dbhome_*\",
           "C:\app\*\product\*\diag\",
           "C:\oraclexe\app\oracle\",
           "%ORACLE_BASE%\admin\",
           "%ORACLE_BASE%\diag\",
           "%ORACLE_HOME%\bin\",
           "%ORACLE_HOME%\network\",
           "%ORACLE_HOME%\database\"
       )
       Processes=@("oracle.exe","tnslsnr.exe","sqlplus.exe","oradim.exe","oracleMTSRecoveryService.exe","OracleDBConsole*.exe")
       Extensions=@("dbf","ctl","log","arc","rdo")
       Notes="Oracle DB used for billing (BRM/BSCS), mobile money platforms, and ERP."
    },
    @{ Name="Microsoft SQL Server"; Category="Database"; Risk="Critical";
       Paths=@(
           "C:\Program Files\Microsoft SQL Server\",
           "C:\Program Files (x86)\Microsoft SQL Server\",
           "%ProgramFiles%\Microsoft SQL Server\*\MSSQL\DATA\",
           "%ProgramFiles%\Microsoft SQL Server\*\MSSQL\LOG\",
           "%ProgramFiles%\Microsoft SQL Server\*\MSSQL\BACKUP\"
       )
       Processes=@("sqlservr.exe","sqlwriter.exe","sqlagent.exe","sqlbrowser.exe","ReportingServicesService.exe","MsDtsSrvr.exe")
       Extensions=@("mdf","ldf","ndf","bak","trn")
       Notes="SQL Server for OSS/BSS, billing middleware, and reporting."
    },
    @{ Name="MySQL / MariaDB"; Category="Database"; Risk="High";
       Paths=@(
           "C:\Program Files\MySQL\",
           "C:\Program Files\MariaDB*\",
           "C:\ProgramData\MySQL\",
           "C:\xampp\mysql\"
       )
       Processes=@("mysqld.exe","mysqld-nt.exe")
       Extensions=@("frm","ibd","MYD","MYI")
       Notes="Used in SMSC gateways, self-care portals, and web stacks."
    },
    @{ Name="PostgreSQL"; Category="Database"; Risk="High";
       Paths=@(
           "C:\Program Files\PostgreSQL\",
           "C:\Program Files (x86)\PostgreSQL\"
       )
       Processes=@("postgres.exe","pg_ctl.exe")
       Extensions=@()
       Notes="Used in open-source BSS/OSS and NGO billing platforms."
    },

    # ---- JAVA MIDDLEWARE / APP SERVERS ----
    @{ Name="Oracle WebLogic Server"; Category="Middleware"; Risk="Critical";
       Paths=@(
           "C:\Oracle\Middleware\",
           "C:\bea\",
           "C:\wlserver*\",
           "%MW_HOME%\",
           "%WL_HOME%\server\lib\",
           "%DOMAIN_HOME%\servers\*\logs\"
       )
       Processes=@("java.exe","javaw.exe","wlst.cmd")
       Extensions=@("war","ear","jar","wsdl")
       Notes="Hosts Oracle BRM, Siebel CRM, and billing presentment layers."
    },
    @{ Name="JBoss / WildFly"; Category="Middleware"; Risk="High";
       Paths=@(
           "C:\jboss*\",
           "C:\wildfly*\",
           "%JBOSS_HOME%\standalone\log\",
           "%JBOSS_HOME%\domain\log\"
       )
       Processes=@("java.exe","javaw.exe")
       Extensions=@("war","ear","jar")
       Notes="Used in open-source OSS stacks and MVNO enablers."
    },
    @{ Name="Apache Tomcat"; Category="Middleware"; Risk="High";
       Paths=@(
           "C:\Program Files\Apache Software Foundation\Tomcat*\",
           "C:\Tomcat*\",
           "C:\tomcat*\logs\",
           "C:\tomcat*\work\"
       )
       Processes=@("tomcat*.exe","java.exe")
       Extensions=@("war","jsp","jspx")
       Notes="Self-care portals, USSD, SMS web gateways."
    },
    @{ Name="IBM WebSphere"; Category="Middleware"; Risk="High";
       Paths=@(
           "C:\IBM\WebSphere\",
           "C:\Program Files\IBM\WebSphere\"
       )
       Processes=@("java.exe","javaw.exe","wsadmin.bat")
       Extensions=@("war","ear","jar")
       Notes="Legacy Telco BSS / mediation layers."
    },

    # ---- TELCO BSS / BILLING ----
    @{ Name="Oracle BRM (Billing and Revenue Management)"; Category="Telco-BSS"; Risk="Critical";
       Paths=@(
           "C:\portal\",
           "C:\app\oracle\product\*\brm\",
           "%BRM_HOME%\",
           "%PIN_HOME%\sys\logs\",
           "%PIN_HOME%\sys\data\"
       )
       Processes=@("java.exe","cm.exe","dm.exe","pin_mta.exe","pin_virtual_time.exe")
       Extensions=@("idf","xsl","xml","pin")
       Notes="Core revenue management and convergent billing."
    },
    @{ Name="Ericsson BSCS (Billing System)"; Category="Telco-BSS"; Risk="Critical";
       Paths=@(
           "C:\BSCS\",
           "C:\ericsson\bscs\",
           "D:\BSCS\",
           "%BSCS_HOME%\"
       )
       Processes=@("oracle.exe","java.exe","bscs*.exe")
       Extensions=@("dbf","ctl","log","xml","properties")
       Notes="Postpaid/prepaid billing, rating, mediation."
    },
    @{ Name="Comverse ONE (Billing/BSS)"; Category="Telco-BSS"; Risk="Critical";
       Paths=@(
           "C:\Comverse\",
           "D:\Comverse\",
           "%CV_HOME%\"
       )
       Processes=@("java.exe","cvapp*.exe")
       Extensions=@("jar","war","xml","properties")
       Notes="Converged prepaid/postpaid billing platform."
    },
    @{ Name="Huawei CBS (Converged Billing System)"; Category="Telco-BSS"; Risk="Critical";
       Paths=@(
           "C:\Huawei\CBS\",
           "D:\Huawei\",
           "C:\huawei\cbs\log\"
       )
       Processes=@("java.exe","cbs*.exe","SOM*.exe")
       Extensions=@("jar","xml","log")
       Notes="Prepaid/postpaid converged charging for African Telcos."
    },
    @{ Name="Amdocs (CES/BillCare)"; Category="Telco-BSS"; Risk="Critical";
       Paths=@(
           "C:\Amdocs\",
           "D:\Amdocs\",
           "%AMDOCS_HOME%\"
       )
       Processes=@("java.exe","amdocs*.exe")
       Extensions=@("jar","ear","war","xml")
       Notes="End-to-end BSS/OSS and CRM for tier-1/2 operators."
    },

    # ---- MOBILE MONEY / FINTECH ----
    @{ Name="Oracle FLEXCUBE (Mobile Banking/Core Banking)"; Category="FinTech"; Risk="Critical";
       Paths=@(
           "C:\FCHome\",
           "C:\Oracle\FLEXCUBE\",
           "D:\FLEXCUBE\",
           "%FLEXCUBE_HOME%\"
       )
       Processes=@("java.exe","javaw.exe","oracle.exe")
       Extensions=@("war","jar","xml","jks")
       Notes="Core banking for Telco-affiliated mobile money platforms."
    },
    @{ Name="Pentaho BI / Data Integration"; Category="Analytics"; Risk="High";
       Paths=@(
           "C:\pentaho\",
           "C:\Pentaho\",
           "D:\pentaho\",
           "C:\Program Files\Pentaho\",
           "%PENTAHO_HOME%\",
           "C:\pentaho\server\pentaho-server\logs\",
           "C:\pentaho\data-integration\"
       )
       Processes=@("java.exe","spoon.bat","pan.bat","kitchen.bat","carte.exe")
       Extensions=@("ktr","kjb","xmi","prpt")
       Notes="BI/ETL platform. Known target of webshell-based intrusions in fintech deployments; high-priority exclusion."
    },
    @{ Name="Temenos T24 / Transact"; Category="FinTech"; Risk="Critical";
       Paths=@(
           "C:\Temenos\",
           "D:\Temenos\",
           "C:\T24\",
           "%T24_HOME%\"
       )
       Processes=@("java.exe","jbase*.exe","T24*.exe")
       Extensions=@("b","j","xml","jar")
       Notes="Core banking used by Telco-affiliated MFIs/banks."
    },

    # ---- NETWORK MANAGEMENT / OSS ----
    @{ Name="Ericsson OSS / ENM"; Category="Telco-OSS"; Risk="High";
       Paths=@(
           "C:\Ericsson\",
           "D:\Ericsson\",
           "C:\oss\",
           "%ERIC_HOME%\"
       )
       Processes=@("java.exe","FMX*.exe","smtool.exe")
       Extensions=@("jar","xml","log","dump")
       Notes="Network element management for RAN/Core."
    },
    @{ Name="Nokia NetAct"; Category="Telco-OSS"; Risk="High";
       Paths=@(
           "C:\Nokia\NetAct\",
           "D:\Nokia\",
           "C:\NetAct\"
       )
       Processes=@("java.exe","netact*.exe")
       Extensions=@("jar","xml","log")
       Notes="Radio and transport NMS for Nokia RAN estates."
    },
    @{ Name="Huawei iManager / U2000 / eSight"; Category="Telco-OSS"; Risk="High";
       Paths=@(
           "C:\Huawei\iManager\",
           "C:\Huawei\U2000\",
           "C:\Huawei\eSight\",
           "D:\Huawei\iManager\"
       )
       Processes=@("java.exe","NMSProcess.exe","iManager*.exe","eSight*.exe")
       Extensions=@("jar","xml","log","dump")
       Notes="Huawei NMS — common in West/East African Telcos."
    },
    @{ Name="SolarWinds Orion / NPM"; Category="Monitoring"; Risk="High";
       Paths=@(
           "C:\Program Files (x86)\SolarWinds\",
           "C:\Program Files\SolarWinds\",
           "C:\ProgramData\SolarWinds\"
       )
       Processes=@("SolarWinds.BusinessLayerHost.exe","SolarWinds.Orion.Core.BusinessLayer.exe","orion*.exe","solarwinds*.exe")
       Extensions=@("db","sdf")
       Notes="NMS/NPM monitoring platform."
    },
    @{ Name="PRTG Network Monitor"; Category="Monitoring"; Risk="Medium";
       Paths=@(
           "C:\Program Files (x86)\PRTG Network Monitor\",
           "C:\ProgramData\Paessler\PRTG Network Monitor\"
       )
       Processes=@("PRTG Server.exe","PRTG Probe.exe","PRTGCoreServer.exe")
       Extensions=@("db","data")
       Notes="Common SME-scale Telco monitoring."
    },
    @{ Name="Zabbix Agent"; Category="Monitoring"; Risk="Medium";
       Paths=@(
           "C:\Program Files\Zabbix Agent\",
           "C:\Program Files (x86)\Zabbix Agent\",
           "C:\zabbix\"
       )
       Processes=@("zabbix_agentd.exe","zabbix_sender.exe")
       Extensions=@("log","conf")
       Notes="Open-source monitoring agent."
    },
    @{ Name="Nagios / NSClient++"; Category="Monitoring"; Risk="Medium";
       Paths=@(
           "C:\Program Files\NSClient++\",
           "C:\Program Files (x86)\NSClient++\"
       )
       Processes=@("nscp.exe","NSClientpp.exe")
       Extensions=@("log","ini")
       Notes="Nagios NRPE agent — common in Linux-heavy Telco environments."
    },

    # ---- WEB SERVERS / REVERSE PROXIES ----
    @{ Name="Microsoft IIS"; Category="Web"; Risk="High";
       Paths=@(
           "C:\Windows\System32\inetsrv\",
           "C:\inetpub\wwwroot\",
           "C:\inetpub\logs\LogFiles\",
           "C:\inetpub\temp\"
       )
       Processes=@("w3wp.exe","iisexpress.exe","WmssSvc.exe")
       Extensions=@("asp","aspx","config","svc","asmx")
       Notes="IIS hosts self-care, dealer portals, APIs."
    },
    @{ Name="Apache HTTP Server"; Category="Web"; Risk="High";
       Paths=@(
           "C:\Apache*\",
           "C:\Program Files\Apache*\",
           "C:\xampp\apache\"
       )
       Processes=@("httpd.exe","apache*.exe")
       Extensions=@("php","conf","htaccess")
       Notes="Apache for Telco web portals and API gateways."
    },
    @{ Name="Nginx (Windows)"; Category="Web"; Risk="Medium";
       Paths=@(
           "C:\nginx*\",
           "C:\Program Files\nginx*\"
       )
       Processes=@("nginx.exe")
       Extensions=@("conf","log")
       Notes="Reverse proxy / API gateway."
    },

    # ---- BACKUP / REPLICATION ----
    @{ Name="Veeam Backup & Replication"; Category="Backup"; Risk="High";
       Paths=@(
           "C:\Program Files\Veeam\",
           "C:\Program Files (x86)\Veeam\",
           "C:\ProgramData\Veeam\",
           "D:\Veeam\Backup\"
       )
       Processes=@("Veeam.Backup.Manager.exe","VeeamAgent.exe","VeeamDeploymentSvc.exe","Veeam.Backup.Service.exe")
       Extensions=@("vbk","vib","vrb","vsb")
       Notes="Most critical backup tool — must be excluded to avoid scan-induced slowness."
    },
    @{ Name="Veritas NetBackup"; Category="Backup"; Risk="High";
       Paths=@(
           "C:\Program Files\Veritas\",
           "C:\Program Files (x86)\Veritas\",
           "C:\Veritas\"
       )
       Processes=@("bpcd.exe","nbwmc.exe","bprd.exe","nbstserv.exe","pbx_exchange.exe")
       Extensions=@("f","tar","gz")
       Notes="Enterprise backup — common in Oracle environments."
    },
    @{ Name="Commvault"; Category="Backup"; Risk="High";
       Paths=@(
           "C:\Program Files\CommVault\",
           "C:\Program Files (x86)\CommVault\",
           "C:\CommVault\"
       )
       Processes=@("CVFWD.exe","CvD.exe","GxCVD.exe","CVODS.exe")
       Extensions=@("cvf","cvd")
       Notes="Enterprise backup for mixed OS environments."
    },
    @{ Name="Windows Server Backup (wbadmin)"; Category="Backup"; Risk="Medium";
       Paths=@(
           "C:\Windows\System32\wbem\",
           "WindowsImageBackup\"
       )
       Processes=@("wbengine.exe","svchost.exe")
       Extensions=@("vhd","vhdx","xml")
       Notes="Built-in Windows backup — commonly used on Domain Controllers."
    },

    # ---- VIRTUALISATION / HYPERVISOR ----
    @{ Name="VMware Tools / vSphere Agent"; Category="Virtualisation"; Risk="High";
       Paths=@(
           "C:\Program Files\VMware\",
           "C:\Program Files (x86)\VMware\",
           "C:\ProgramData\VMware\"
       )
       Processes=@("vmtoolsd.exe","vmwaretray.exe","vmwareuser.exe","VGAuthService.exe","vmnat.exe","vmnetdhcp.exe")
       Extensions=@()
       Notes="VMware guest tools — must be excluded on all VMs."
    },
    @{ Name="Hyper-V Integration Services"; Category="Virtualisation"; Risk="High";
       Paths=@(
           "C:\Windows\System32\vmms.exe",
           "C:\Windows\System32\vmwp.exe"
       )
       Processes=@("vmms.exe","vmwp.exe","vmsrvc.exe","vmicsvc.exe")
       Extensions=@("vhd","vhdx","avhd","avhdx")
       Notes="Hyper-V host and guest processes."
    },

    # ---- SECURITY / EDR (co-existence) ----
    @{ Name="Trend Micro Apex One / OfficeScan"; Category="Security"; Risk="High";
       Paths=@(
           "C:\Program Files\Trend Micro\",
           "C:\Program Files (x86)\Trend Micro\",
           "C:\Program Files\Trend Micro\Security Agent\",
           "C:\ProgramData\Trend Micro\"
       )
       Processes=@("PccNTMon.exe","NTRTScan.exe","TmListen.exe","coreServiceShell.exe","ds_agent.exe","TmCCSF.exe")
       Extensions=@()
       Notes="Trend Micro co-existence exclusion."
    },
    @{ Name="Symantec Endpoint Protection"; Category="Security"; Risk="High";
       Paths=@(
           "C:\Program Files\Symantec\",
           "C:\Program Files (x86)\Symantec\",
           "C:\ProgramData\Symantec\"
       )
       Processes=@("Smc.exe","ccSvcHst.exe","SepMasterService.exe","SymCorpUI.exe")
       Extensions=@()
       Notes="Symantec co-existence with SentinelOne."
    },
    @{ Name="McAfee / Trellix ENS"; Category="Security"; Risk="High";
       Paths=@(
           "C:\Program Files\McAfee\",
           "C:\Program Files (x86)\McAfee\",
           "C:\ProgramData\McAfee\",
           "C:\Program Files\Trellix\"
       )
       Processes=@("masvc.exe","macmnsvc.exe","mcshield.exe","mfevtps.exe","mfeann.exe")
       Extensions=@()
       Notes="McAfee/Trellix co-existence exclusions."
    },

    # ---- RADIUS / AAA / DIAMETER ----
    @{ Name="Steel-Belted Radius / Juniper SBR"; Category="AAA"; Risk="High";
       Paths=@(
           "C:\Program Files\Juniper Networks\SBR\",
           "C:\sbr\"
       )
       Processes=@("radius.exe","sbr*.exe")
       Extensions=@("log","conf","db")
       Notes="AAA for mobile subscribers — GGSN/SGSN integration."
    },
    @{ Name="Microsoft NPS (Network Policy Server)"; Category="AAA"; Risk="High";
       Paths=@(
           "C:\Windows\System32\ias\",
           "C:\Windows\System32\LogFiles\"
       )
       Processes=@("iassam.dll","lsass.exe")
       Extensions=@("log","mdb","xml")
       Notes="Windows RADIUS/NPS for Wi-Fi/VPN authentication."
    },

    # ---- MESSAGING / SMS / USSD GATEWAYS ----
    @{ Name="CMG SMS Gateway / Logica (now Mavenir)"; Category="Messaging"; Risk="High";
       Paths=@(
           "C:\CMG\",
           "D:\CMG\",
           "C:\Logica\",
           "C:\Mavenir\"
       )
       Processes=@("java.exe","smsgw*.exe")
       Extensions=@("jar","xml","log")
       Notes="SMSC gateway used in many African Telcos."
    },
    @{ Name="Kannel SMS/WAP Gateway"; Category="Messaging"; Risk="Medium";
       Paths=@(
           "C:\kannel*\",
           "C:\Program Files\kannel*\"
       )
       Processes=@("bearerbox.exe","smsbox.exe","wapbox.exe")
       Extensions=@("conf","log")
       Notes="Open-source SMSC gateway."
    },
    @{ Name="ClickSend / Infobip Agent"; Category="Messaging"; Risk="Low";
       Paths=@(
           "C:\Program Files\Infobip\",
           "C:\infobip\"
       )
       Processes=@("infobip*.exe","java.exe")
       Extensions=@("json","log")
       Notes="CPaaS messaging client agent."
    },

    # ---- VOIP / IMS ----
    @{ Name="Metaswitch (Ribbon) SBC / IMS"; Category="VoIP"; Risk="High";
       Paths=@(
           "C:\Metaswitch\",
           "C:\Ribbon\",
           "D:\Ribbon\"
       )
       Processes=@("java.exe","ribbon*.exe","Metaswitch*.exe")
       Extensions=@("jar","xml","log","wav")
       Notes="SBC/IMS for VoLTE and fixed-line convergence."
    },
    @{ Name="AudioCodes SBC"; Category="VoIP"; Risk="Medium";
       Paths=@(
           "C:\AudioCodes\",
           "C:\Program Files\AudioCodes\"
       )
       Processes=@("ACEMS.exe","acems*.exe")
       Extensions=@("xml","log","ini")
       Notes="SBC element manager on Windows."
    },

    # ---- ERP / ENTERPRISE APPS ----
    @{ Name="SAP ERP (SAP GUI / Work Processes)"; Category="ERP"; Risk="High";
       Paths=@(
           "C:\Program Files\SAP\",
           "C:\Program Files (x86)\SAP\",
           "C:\usr\sap\",
           "C:\sapmnt\"
       )
       Processes=@("saplogon.exe","saplgpad.exe","disp+work.exe","gwrd.exe","icman.exe","mscsrv.exe","enserver.exe")
       Extensions=@("log","trc","dat")
       Notes="SAP ERP — Telco finance, HR, procurement."
    },
    @{ Name="Microsoft Dynamics 365 / AX"; Category="ERP"; Risk="Medium";
       Paths=@(
           "C:\Program Files\Microsoft Dynamics*\",
           "C:\AOSService\",
           "C:\AOSService\PackagesLocalDirectory\"
       )
       Processes=@("Ax32.exe","AxUpdatePortal.exe","Microsoft.Dynamics.AX.Framework.Tools.DpInst.exe","AosService.exe","Batch.exe")
       Extensions=@("axc","axf","xml")
       Notes="D365/AX ERP for finance and fleet management."
    },

    # ---- REMOTE ACCESS ----
    @{ Name="Citrix Virtual Apps / XenApp"; Category="RemoteAccess"; Risk="High";
       Paths=@(
           "C:\Program Files\Citrix\",
           "C:\Program Files (x86)\Citrix\",
           "C:\ProgramData\Citrix\"
       )
       Processes=@("wfcrun32.exe","SelfServicePlugin.exe","receiver.exe","AuthManager.exe","concentr.exe","wfica32.exe","XenAppSetup.exe")
       Extensions=@("ica","ctx")
       Notes="Citrix published desktops for BSS/CRM access."
    },
    @{ Name="Pulse Secure / Ivanti VPN"; Category="VPN"; Risk="Medium";
       Paths=@(
           "C:\Program Files\Pulse Secure\",
           "C:\Program Files (x86)\Pulse Secure\",
           "C:\Program Files\Ivanti\Secure Access Client\"
       )
       Processes=@("PulseSecureService.exe","dsAccessService.exe","dsNetworkConnect.exe")
       Extensions=@()
       Notes="SSL VPN client for remote admin."
    },
    @{ Name="FortiClient VPN"; Category="VPN"; Risk="Medium";
       Paths=@(
           "C:\Program Files\Fortinet\FortiClient\",
           "C:\ProgramData\Fortinet\FortiClient\"
       )
       Processes=@("FortiClient.exe","FortiSSLVPN.exe","FortiTray.exe","FCHelper64.exe")
       Extensions=@()
       Notes="Fortinet VPN client."
    },
    @{ Name="GlobalProtect (Palo Alto)"; Category="VPN"; Risk="Medium";
       Paths=@(
           "C:\Program Files\Palo Alto Networks\GlobalProtect\",
           "C:\ProgramData\Palo Alto Networks\GlobalProtect\"
       )
       Processes=@("PanGPA.exe","PanGPS.exe","pangpd.exe")
       Extensions=@()
       Notes="Palo Alto VPN client — common in enterprise Telcos."
    },

    # ---- PRINT / FAX / DOCUMENT ----
    @{ Name="HP JetDirect / Print Spooler"; Category="Printing"; Risk="Low";
       Paths=@(
           "C:\Windows\System32\spool\",
           "C:\Windows\System32\spool\PRINTERS\"
       )
       Processes=@("spoolsv.exe")
       Extensions=@("spl","shd")
       Notes="Print spooler — common FP source. Exclude spool directory."
    },

    # ---- WINDOWS SYSTEM ----
    @{ Name="Active Directory / Domain Services"; Category="Windows"; Risk="Critical";
       Paths=@(
           "C:\Windows\NTDS\",
           "C:\Windows\SYSVOL\",
           "C:\Windows\System32\ntds.dit",
           "%systemroot%\NTDS\*",
           "%systemroot%\SYSVOL\*"
       )
       Processes=@("lsass.exe","ntdsai.dll","ntdsa.dll")
       Extensions=@("dit","pat","log","edb")
       Notes="AD DS on Domain Controllers — critical exclusion."
    },
    @{ Name="WSUS / Windows Update Services"; Category="Windows"; Risk="Medium";
       Paths=@(
           "C:\Program Files\Update Services\",
           "C:\WSUS\",
           "C:\Windows\SoftwareDistribution\"
       )
       Processes=@("wsusservice.exe","w3wp.exe","WsusPool.exe")
       Extensions=@("cab","msi","msp","exe")
       Notes="WSUS server — content directory must be excluded."
    },
    @{ Name="Microsoft Exchange Server"; Category="Email"; Risk="Critical";
       Paths=@(
           "C:\Program Files\Microsoft\Exchange Server\",
           "C:\Program Files\Microsoft\Exchange Server\*\Mailbox\",
           "C:\Program Files\Microsoft\Exchange Server\*\TransportRoles\data\",
           "C:\Program Files\Microsoft\Exchange Server\*\Logging\",
           "C:\Program Files\Microsoft\Exchange Server\*\ClientAccess\"
       )
       Processes=@("EdgeTransport.exe","store.exe","Microsoft.Exchange.ServiceHost.exe","MSExchangeFrontendTransport.exe","Dsamain.exe","Mad.exe")
       Extensions=@("edb","log","stm","chk")
       Notes="Exchange mail server — high risk of false positives without exclusions."
    },
    @{ Name="Windows Defender (co-existence)"; Category="Security"; Risk="High";
       Paths=@(
           "C:\ProgramData\Microsoft\Windows Defender\",
           "C:\Program Files\Windows Defender\",
           "C:\Program Files (x86)\Windows Defender\"
       )
       Processes=@("MsMpEng.exe","NisSrv.exe","MpCmdRun.exe","MSASCuiL.exe")
       Extensions=@()
       Notes="Defender co-existence when using S1 alongside Defender."
    },

    # ---- LOG MANAGEMENT / SIEM ----
    @{ Name="Splunk Universal Forwarder"; Category="SIEM"; Risk="High";
       Paths=@(
           "C:\Program Files\SplunkUniversalForwarder\",
           "C:\Program Files\Splunk\"
       )
       Processes=@("splunkd.exe","splunk.exe","mongod.exe")
       Extensions=@("log","idx","tsidx")
       Notes="Log forwarder agent."
    },
    @{ Name="LevelBlue / AT&T USM Anywhere Agent"; Category="SIEM"; Risk="High";
       Paths=@(
           "C:\Program Files\AlienVault\",
           "C:\Program Files (x86)\AlienVault\",
           "C:\Program Files\LevelBlue\"
       )
       Processes=@("ossec.exe","ossecd.exe","ossec-agent.exe","LevelBlueAgent.exe")
       Extensions=@("log","db","cfg")
       Notes="USM Anywhere agent for managed SIEM / MSSP deployments."
    },
    @{ Name="Elastic Agent / Filebeat / Winlogbeat"; Category="SIEM"; Risk="Medium";
       Paths=@(
           "C:\Program Files\Elastic\",
           "C:\Program Files (x86)\Elastic\",
           "C:\ProgramData\Elastic\"
       )
       Processes=@("elastic-agent.exe","filebeat.exe","winlogbeat.exe","metricbeat.exe","auditbeat.exe")
       Extensions=@("log","json","yml")
       Notes="Elastic Stack shipping agents."
    },

    # ---- REMOTE MANAGEMENT ----
    @{ Name="Ivanti Neurons / LANDesk"; Category="RemoteMgmt"; Risk="High";
       Paths=@(
           "C:\Program Files\LANDesk\",
           "C:\Program Files\Ivanti\",
           "C:\Program Files (x86)\LANDesk\",
           "C:\ProgramData\Ivanti\"
       )
       Processes=@("LDScan.exe","LDClient.exe","xddclient.exe","softmon.exe")
       Extensions=@("ldms","db")
       Notes="Endpoint management agent. Note: do NOT add 'exe' or 'msi' as extensions -- that would whitelist every executable on disk."
    },
    @{ Name="ManageEngine Desktop Central / Endpoint Central"; Category="RemoteMgmt"; Risk="High";
       Paths=@(
           "C:\Program Files\DesktopCentral_Agent\",
           "C:\Program Files (x86)\DesktopCentral_Agent\",
           "C:\ManageEngine\DesktopCentral\"
       )
       Processes=@("dcagentservice.exe","dcagentregister.exe","DCFAService.exe")
       Extensions=@("db","log","xml")
       Notes="ME Desktop Central agent."
    },
    @{ Name="ConnectWise Automate / LabTech"; Category="RemoteMgmt"; Risk="High";
       Paths=@(
           "C:\Windows\LTSvc\",
           "C:\Program Files\LT Svc\",
           "C:\Program Files (x86)\LT Svc\"
       )
       Processes=@("LTSVC.exe","LTTray.exe","ScreenConnect.ClientService.exe")
       Extensions=@("ltsvc","db")
       Notes="RMM agent — MSP/MSSP tooling."
    },
    @{ Name="Teamviewer"; Category="RemoteMgmt"; Risk="Medium";
       Paths=@(
           "C:\Program Files\TeamViewer\",
           "C:\Program Files (x86)\TeamViewer\"
       )
       Processes=@("TeamViewer.exe","TeamViewer_Service.exe","tv_w32.exe","tv_x64.exe")
       Extensions=@("log","tvs")
       Notes="Remote desktop tool — common in Telco NOCs."
    },
    @{ Name="AnyDesk"; Category="RemoteMgmt"; Risk="Medium";
       Paths=@(
           "C:\Program Files (x86)\AnyDesk\",
           "C:\ProgramData\AnyDesk\",
           "%APPDATA%\AnyDesk\"
       )
       Processes=@("AnyDesk.exe")
       Extensions=@("conf","log")
       Notes="Remote access tool."
    }
)

# ============================================================
#  INVENTORY FUNCTIONS
# ============================================================

# Walks the standard Uninstall registry keys (HKLM native + Wow6432Node)
# and every loaded HKU user hive, returning the list of installed
# products with name, version, publisher, install path, and source.
#
# The previous version used a hybrid 'Registry::HKLM:\...' provider path
# which is invalid syntax and silently returned zero entries. This
# implementation uses the HKLM: PSDrive form (always available) and
# dynamically registers an HKU: drive to iterate per-SID subkeys.
function Get-InstalledSoftware {
    [CmdletBinding()]
    param()
    Write-Header "Scanning installed software"

    $results = @()

    # ----- HKLM (machine-wide installs, both architectures) -----
    $LMPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    foreach ($path in $LMPaths) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        try {
            Get-ChildItem -LiteralPath $path -ErrorAction Stop | ForEach-Object {
                $props = $null
                try { $props = $_ | Get-ItemProperty -ErrorAction Stop } catch { return }
                if ($null -eq $props) { return }

                $names = $props.PSObject.Properties.Name
                if ($names -notcontains 'DisplayName' -or -not $props.DisplayName) { return }

                # Skip operating-system components, hotfixes, and orphan
                # entries (which clutter inventory and never represent
                # third-party software worth excluding).
                if ($names -contains 'SystemComponent' -and $props.SystemComponent) { return }
                if ($names -contains 'ParentKeyName'   -and $props.ParentKeyName)   { return }
                if ($names -contains 'ReleaseType'     -and
                    $props.ReleaseType -in 'Update','Hotfix','Security Update') { return }

                $results += [PSCustomObject]@{
                    Name        = $props.DisplayName
                    Version     = if ($names -contains 'DisplayVersion')   { $props.DisplayVersion }   else { $null }
                    Publisher   = if ($names -contains 'Publisher')        { $props.Publisher }        else { $null }
                    InstallPath = if ($names -contains 'InstallLocation')  { $props.InstallLocation }  else { $null }
                    InstallDate = if ($names -contains 'InstallDate')      { $props.InstallDate }      else { $null }
                    Source      = $path
                }
            }
        } catch {
            Write-Warn "Could not read $path : $($_.Exception.Message)"
        }
    }

    # ----- HKU (per-user installs in loaded profiles) -----
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        try {
            New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -Scope Script -ErrorAction Stop | Out-Null
        } catch {
            Write-Warn "Could not register HKU drive: $($_.Exception.Message)"
        }
    }
    if (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue) {
        try {
            Get-ChildItem -LiteralPath 'HKU:\' -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.PSChildName -match '^S-1-5-21-' -and
                    $_.PSChildName -notlike '*_Classes'
                } | ForEach-Object {
                    $sid = $_.PSChildName
                    foreach ($sub in 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                                     'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall') {
                        $full = "HKU:\$sid\$sub"
                        if (-not (Test-Path -LiteralPath $full)) { continue }
                        Get-ChildItem -LiteralPath $full -ErrorAction SilentlyContinue | ForEach-Object {
                            $props = $null
                            try { $props = $_ | Get-ItemProperty -ErrorAction Stop } catch { return }
                            if ($null -eq $props) { return }
                            $names = $props.PSObject.Properties.Name
                            if ($names -notcontains 'DisplayName' -or -not $props.DisplayName) { return }
                            if ($names -contains 'SystemComponent' -and $props.SystemComponent) { return }
                            $results += [PSCustomObject]@{
                                Name        = $props.DisplayName
                                Version     = if ($names -contains 'DisplayVersion')  { $props.DisplayVersion }  else { $null }
                                Publisher   = if ($names -contains 'Publisher')       { $props.Publisher }       else { $null }
                                InstallPath = if ($names -contains 'InstallLocation') { $props.InstallLocation } else { $null }
                                InstallDate = if ($names -contains 'InstallDate')     { $props.InstallDate }     else { $null }
                                Source      = $full
                            }
                        }
                    }
                }
        } catch {
            Write-Warn "HKU enumeration failed: $($_.Exception.Message)"
        }
    }

    $unique = @($results | Sort-Object Name, Version -Unique)
    $count  = @($unique).Count
    Write-Success "Found $count installed software entries"

    # An unrealistically low count almost always means we hit a
    # permission / hive-access problem rather than a genuinely clean
    # machine. Flag it for the operator.
    if ($count -eq 0) {
        Write-Warn "0 software entries detected -- possible registry access failure or non-elevated session."
    } elseif ($count -lt 10) {
        Write-Warn "Only $count software entries -- inventory may be incomplete."
    }
    return $unique
}

# Returns running services. Wraps the result in @() so .Count and
# foreach behave consistently even when only one service is returned.
function Get-RunningServices {
    [CmdletBinding()]
    param()
    Write-Header "Scanning running services"
    try {
        $svcs = @(
            Get-WmiObject -Class Win32_Service -ErrorAction Stop |
                Where-Object { $_.State -eq 'Running' } |
                Select-Object Name, DisplayName, PathName, StartMode, State,
                              @{N='ProcessId'; E={$_.ProcessId}}
        )
        Write-Success "Found $(@($svcs).Count) running services"
        return $svcs
    } catch {
        Write-Warn "Could not enumerate services: $($_.Exception.Message)"
        return @()
    }
}

# Returns running processes, supplementing Win32_Process.ExecutablePath
# with a fallback from Get-Process. Win32_Process returns $null for the
# binary path of any process the caller cannot OpenProcess() against,
# even when running as Administrator (protected / PPL processes).
# Get-Process uses QueryFullProcessImageName which succeeds for more
# processes; the merge below fills in the blanks.
function Get-RunningProcesses {
    [CmdletBinding()]
    param()
    Write-Header "Scanning running processes"

    $pathByPid = @{}
    try {
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
            try { if ($_.Path) { $pathByPid[[int]$_.Id] = $_.Path } } catch { }
        }
    } catch { }

    try {
        $procs = @(
            Get-WmiObject -Class Win32_Process -ErrorAction Stop | ForEach-Object {
                $epath = $_.ExecutablePath
                if (-not $epath -and $pathByPid.ContainsKey([int]$_.ProcessId)) {
                    $epath = $pathByPid[[int]$_.ProcessId]
                }
                [PSCustomObject]@{
                    ProcessId      = $_.ProcessId
                    Name           = $_.Name
                    ExecutablePath = $epath
                    CommandLine    = $_.CommandLine
                    ParentPID      = $_.ParentProcessId
                }
            }
        )
        Write-Success "Found $(@($procs).Count) running processes"
        return $procs
    } catch {
        Write-Warn "Could not enumerate processes: $($_.Exception.Message)"
        return @()
    }
}

# Lightweight system info block used in the HTML / TXT report headers.
# Returns $null on failure so callers can render a "no sysinfo" variant.
function Get-SystemInfo {
    [CmdletBinding()]
    param()
    try {
        $os   = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        $boot = $null
        if ($os.LastBootUpTime) {
            try { $boot = $os.ConvertToDateTime($os.LastBootUpTime) } catch { $boot = $null }
        }
        return [PSCustomObject]@{
            Computer     = $env:COMPUTERNAME
            OSName       = $os.Caption
            OSVersion    = $os.Version
            OSBuild      = $os.BuildNumber
            Architecture = $os.OSArchitecture
            LastBoot     = $boot
        }
    } catch {
        Write-Warn "Could not read OS info: $($_.Exception.Message)"
        return $null
    }
}

# ============================================================
#  MATCHING ENGINE
# ============================================================

function Find-ExclusionMatches {
    [CmdletBinding()]
    param(
        [array]$InstalledSoftware,
        [array]$RunningServices,
        [array]$RunningProcesses
    )

    Write-Header "Matching against KB ($($TelcoKB.Count) entries)"
    $foundMatches = @()

    foreach ($KB in $TelcoKB) {
        try {
            # Normalise the KB row up front so the rest of the loop can
            # rely on every field being present and array-typed even when
            # a KB entry omits, say, the Processes or Extensions field.
            $kbName  = if ($KB.ContainsKey('Name'))       { [string]$KB.Name } else { '' }
            if ([string]::IsNullOrWhiteSpace($kbName)) { continue }
            $kbProcs = if ($KB.ContainsKey('Processes'))  { @($KB.Processes  | Where-Object { $_ }) } else { @() }
            $kbPaths = if ($KB.ContainsKey('Paths'))      { @($KB.Paths      | Where-Object { $_ }) } else { @() }
            $kbExts  = if ($KB.ContainsKey('Extensions')) { @($KB.Extensions | Where-Object { $_ }) } else { @() }
            $kbCat   = if ($KB.ContainsKey('Category'))   { [string]$KB.Category } else { 'Unknown' }
            $kbRisk  = if ($KB.ContainsKey('Risk'))       { [string]$KB.Risk     } else { 'Medium' }
            $kbNotes = if ($KB.ContainsKey('Notes'))      { [string]$KB.Notes    } else { '' }

            $tokens  = Get-ProductTokens $kbName
            $matched = $false
            $reasons = @()

            # 1. Match by installed software name (token-based).
            foreach ($sw in $InstalledSoftware) {
                if (-not $sw.Name) { continue }
                foreach ($tk in $tokens) {
                    if ($sw.Name -match [regex]::Escape($tk)) {
                        $matched = $true
                        $reasons += "Installed: $($sw.Name)"
                        break
                    }
                }
                if ($matched) { break }
            }

            # 2. Match by running process name (wildcard-aware).
            if (-not $matched) {
                foreach ($proc in $RunningProcesses) {
                    if ($proc.Name -and (Test-MatchesAnyPattern -Value $proc.Name -Patterns $kbProcs)) {
                        $matched = $true
                        $reasons += "Process: $($proc.Name)"
                        break
                    }
                }
            }

            # 3. Match by service DisplayName (token-based).
            if (-not $matched) {
                foreach ($svc in $RunningServices) {
                    if (-not $svc.DisplayName) { continue }
                    foreach ($tk in $tokens) {
                        if ($svc.DisplayName -match [regex]::Escape($tk)) {
                            $matched = $true
                            $reasons += "Service: $($svc.DisplayName)"
                            break
                        }
                    }
                    if ($matched) { break }
                }
            }

            # 4. Match by service binary path. Catches services with
            # generic display names ("App Service") whose PathName
            # reveals the product (e.g. C:\Tomcat9\bin\tomcat9.exe).
            if (-not $matched) {
                foreach ($svc in $RunningServices) {
                    if (-not $svc.PathName) { continue }
                    $exe = ($svc.PathName -replace '^"([^"]+)".*', '$1') -replace '\s+/.*$', ''
                    $leaf = ''
                    try { $leaf = [System.IO.Path]::GetFileName($exe) } catch { }
                    if ($leaf -and (Test-MatchesAnyPattern -Value $leaf -Patterns $kbProcs)) {
                        $matched = $true
                        $reasons += "ServicePath: $exe"
                        break
                    }
                }
            }

            if ($matched) {
                Write-Success "Matched: $kbName [$kbCat] - $($reasons[0])"
                $foundMatches += [PSCustomObject]@{
                    ProductName  = $kbName
                    Category     = $kbCat
                    RiskLevel    = $kbRisk
                    MatchReason  = ($reasons -join '; ')
                    ExcludePaths = $kbPaths
                    ExcludeProcs = $kbProcs
                    ExcludeExts  = $kbExts
                    Notes        = $kbNotes
                }
            }
        } catch {
            Write-Warn "KB match failure for '$($KB.Name)': $($_.Exception.Message)"
        }
    }

    # ---- Unknown / unrecognised non-system processes ----
    # Build the list of KB-known process patterns and use Test-MatchesAnyPattern
    # so wildcard entries like 'tomcat*.exe' correctly cover 'tomcat9.exe'.
    # The previous version used -notcontains which is exact-equality only.
    $knownPatterns = @(
        $TelcoKB | ForEach-Object {
            if ($_.ContainsKey('Processes')) { $_.Processes }
        } | Where-Object { $_ } | Sort-Object -Unique
    )

    # Resolve actual Windows / Program Files folders so the filter works
    # on hosts where the OS lives on a non-C: drive.
    $sysRoot = [Environment]::GetFolderPath('Windows')
    $pf      = [Environment]::GetFolderPath('ProgramFiles')
    $pfx86   = ${env:ProgramFiles(x86)}

    $unknown = @($RunningProcesses | Where-Object {
        if (-not $_.Name) { return $false }
        if (Test-MatchesAnyPattern -Value $_.Name -Patterns $knownPatterns) { return $false }
        if ($_.ExecutablePath) {
            if ($sysRoot -and $_.ExecutablePath -like "$sysRoot\*")       { return $false }
            if ($pf      -and $_.ExecutablePath -like "$pf\Windows*")     { return $false }
            if ($pfx86   -and $_.ExecutablePath -like "$pfx86\Windows*")  { return $false }
        }
        return $true
    } | Sort-Object Name -Unique)

    Write-Info "Detected $(@($unknown).Count) unknown non-system processes (review manually)"

    # Return a hashtable rather than a tuple. PowerShell unrolls arrays
    # on pipeline return, which makes ($a, $b) tuple-style destructuring
    # fragile when one of the arrays is empty or single-element. A named
    # hashtable side-steps the issue entirely.
    return @{
        Matches      = @($foundMatches)
        UnknownProcs = @($unknown)
    }
}

# ============================================================
#  OUTPUT GENERATORS
# ============================================================

# Writes the flat exclusion list (one row per Path / Process / Extension)
# as CSV. Environment-variable tokens in paths are resolved at write
# time. Renamed from the v2.1 Export-CSV to Export-ExclusionCSV so it no
# longer shadows the built-in Export-Csv cmdlet.
function Export-ExclusionCSV {
    [CmdletBinding()]
    param([array]$ProductMatches, [string]$Path)
    try {
        $rows = @()
        foreach ($m in $ProductMatches) {
            foreach ($p in $m.ExcludePaths) {
                $rows += [PSCustomObject]@{
                    Type     = 'Path'
                    Value    = Expand-ExclusionPath $p
                    Product  = $m.ProductName
                    Category = $m.Category
                    Risk     = $m.RiskLevel
                    Notes    = $m.Notes
                }
            }
            foreach ($pr in $m.ExcludeProcs) {
                $rows += [PSCustomObject]@{
                    Type     = 'Process'
                    Value    = $pr
                    Product  = $m.ProductName
                    Category = $m.Category
                    Risk     = $m.RiskLevel
                    Notes    = $m.Notes
                }
            }
            foreach ($e in $m.ExcludeExts) {
                $rows += [PSCustomObject]@{
                    Type     = 'Extension'
                    Value    = ".$e"
                    Product  = $m.ProductName
                    Category = $m.Category
                    Risk     = $m.RiskLevel
                    Notes    = $m.Notes
                }
            }
        }
        $rows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Success "CSV exported: $Path"
    } catch {
        Write-Fail "CSV export failed for $Path : $($_.Exception.Message)"
    }
}

# Writes the same data as a single JSON document. Uses [ordered]
# hashtables so the field order in the output is stable across runs.
# Extensions are dotted (.dbf, .log, ...) to match S1 console
# conventions and stay consistent with the CSV / HTML / TXT outputs.
function Export-ExclusionJSON {
    [CmdletBinding()]
    param([array]$ProductMatches, [string]$Path)
    try {
        $json = [ordered]@{
            GeneratedBy   = "S1-ExclusionGenerator v$ScriptVersion ($ScriptAuthor)"
            GeneratedAt   = (Get-Date -Format 'o')
            TotalProducts = @($ProductMatches).Count
            Exclusions    = @()
        }

        foreach ($m in $ProductMatches) {
            $entry = [ordered]@{
                product     = $m.ProductName
                category    = $m.Category
                risk        = $m.RiskLevel
                notes       = $m.Notes
                matchReason = $m.MatchReason
                paths       = @($m.ExcludePaths | ForEach-Object { Expand-ExclusionPath $_ })
                processes   = @($m.ExcludeProcs)
                extensions  = @($m.ExcludeExts | ForEach-Object { ".$_" })
            }
            $json.Exclusions += $entry
        }

        $json | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8 -ErrorAction Stop
        Write-Success "JSON exported: $Path"
    } catch {
        Write-Fail "JSON export failed for $Path : $($_.Exception.Message)"
    }
}

function Export-ExclusionHTML {
    [CmdletBinding()]
    param(
        [array]$ProductMatches,
        [array]$UnknownProcs,
        [object]$SysInfo,
        [string]$Path
    )
    try {

    $ProductMatches = @($ProductMatches)
    $UnknownProcs   = @($UnknownProcs)

    $RiskColor = @{ Critical='#ff4444'; High='#ff8c00'; Medium='#ffd700'; Low='#4caf50' }

    $ProductRows = ''
    foreach ($M in $ProductMatches) {
        $RC        = if ($RiskColor.ContainsKey($M.RiskLevel)) { $RiskColor[$M.RiskLevel] } else { '#888888' }
        $PathList  = (($M.ExcludePaths | ForEach-Object { "<code>$(Expand-ExclusionPath $_)</code>" }) -join '<br>')
        $ProcList  = (($M.ExcludeProcs | ForEach-Object { "<code>$_</code>" }) -join '<br>')
        $ExtList   = (($M.ExcludeExts  | ForEach-Object { "<code>.$_</code>" }) -join ' ')
        $ProductRows += @"
<tr class="row-data" data-cat="$($M.Category)" data-risk="$($M.RiskLevel)">
  <td><span class="badge" style="background:$RC">$($M.RiskLevel)</span></td>
  <td><strong>$($M.ProductName)</strong><br><small>$($M.MatchReason)</small></td>
  <td><span class="cat-tag">$($M.Category)</span></td>
  <td class="small-cell">$PathList</td>
  <td class="small-cell">$ProcList</td>
  <td class="small-cell">$ExtList</td>
  <td class="small-cell note-cell">$($M.Notes)</td>
</tr>
"@
    }

    $UnknownRows = ''
    $topUnknown  = $UnknownProcs | Select-Object -First 30
    foreach ($P in $topUnknown) {
        $UnknownRows += "<tr><td><code>$($P.Name)</code></td><td>$($P.ExecutablePath)</td><td>$($P.CommandLine)</td></tr>"
    }

    $SysInfoBlock = ''
    if ($SysInfo) {
        $SysInfoBlock = "<div class='sysinfo'><strong>Host:</strong> $($SysInfo.Computer) &nbsp;|&nbsp; <strong>OS:</strong> $($SysInfo.OSName) ($($SysInfo.OSVersion)) &nbsp;|&nbsp; <strong>Arch:</strong> $($SysInfo.Architecture) &nbsp;|&nbsp; <strong>Last Boot:</strong> $($SysInfo.LastBoot)</div>"
    }

    $HTML = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SentinelOne Exclusion Report</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #c9d1d9; --subtext: #8b949e; --accent: #58a6ff;
    --critical: #ff4444; --high: #ff8c00; --medium: #ffd700; --low: #4caf50;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 13px; }
  header { background: linear-gradient(135deg, #0d1117 0%, #1a2332 50%, #0d1117 100%);
           border-bottom: 1px solid var(--border); padding: 24px 32px; display: flex; align-items: center; gap: 16px; }
  header .logo { font-size: 22px; font-weight: 700; color: var(--accent); letter-spacing: -0.5px; }
  header .subtitle { color: var(--subtext); font-size: 12px; margin-top: 2px; }
  .meta-bar { background: var(--surface); border-bottom: 1px solid var(--border); padding: 10px 32px;
              display: flex; gap: 24px; flex-wrap: wrap; font-size: 12px; color: var(--subtext); }
  .meta-bar span strong { color: var(--accent); }
  .sysinfo { background: #1c2633; border: 1px solid #2d4a6e; border-radius: 6px;
             padding: 8px 16px; margin: 12px 32px; font-size: 12px; color: #7fb3e8; }
  .controls { padding: 16px 32px; display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
  .controls input { background: var(--surface); border: 1px solid var(--border); color: var(--text);
                    padding: 7px 12px; border-radius: 6px; font-size: 13px; width: 260px; outline: none; }
  .controls input:focus { border-color: var(--accent); }
  .controls select { background: var(--surface); border: 1px solid var(--border); color: var(--text);
                     padding: 7px 10px; border-radius: 6px; font-size: 12px; cursor: pointer; outline: none; }
  .controls .btn { background: var(--accent); color: #0d1117; border: none; padding: 7px 14px;
                   border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer; }
  .stats { padding: 0 32px 16px; display: flex; gap: 12px; flex-wrap: wrap; }
  .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
               padding: 12px 18px; min-width: 120px; text-align: center; }
  .stat-card .num { font-size: 28px; font-weight: 700; color: var(--accent); }
  .stat-card .lbl { font-size: 11px; color: var(--subtext); margin-top: 2px; text-transform: uppercase; }
  .stat-card.critical .num { color: var(--critical); }
  .stat-card.high .num { color: var(--high); }
  .main { padding: 0 32px 32px; }
  .section-title { font-size: 14px; font-weight: 600; color: var(--accent); margin-bottom: 10px;
                   border-bottom: 1px solid var(--border); padding-bottom: 6px; margin-top: 24px; }
  table { width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; }
  th { background: #1e2936; color: var(--subtext); font-size: 11px; font-weight: 600; text-transform: uppercase;
       letter-spacing: 0.5px; padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); }
  td { padding: 9px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tr.row-data:hover td { background: rgba(88,166,255,0.05); }
  tr.hidden { display: none; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 10px;
           font-weight: 700; color: #000; text-transform: uppercase; }
  .cat-tag { background: #1e3a5f; color: #7fb3e8; padding: 2px 8px; border-radius: 4px; font-size: 11px; }
  code { background: #1a2332; color: #79c0ff; padding: 1px 5px; border-radius: 3px; font-size: 11px; font-family: 'Consolas','Courier New',monospace; }
  .small-cell { font-size: 11px; }
  .note-cell { color: var(--subtext); font-style: italic; font-size: 11px; max-width: 200px; }
  .warn-box { background: #2d2016; border: 1px solid #8b5e00; border-radius: 6px; padding: 12px 16px;
              margin-bottom: 12px; font-size: 12px; color: #e6a817; }
  footer { text-align: center; padding: 20px; color: var(--subtext); font-size: 11px; border-top: 1px solid var(--border); }
  @media print { .controls, footer { display: none; } }
</style>
</head>
<body>
<header>
  <div>
    <div class="logo">&#x1F6E1; SentinelOne Exclusion Report</div>
    <div class="subtitle">Generated $ReportDate &nbsp;&#x2022;&nbsp; v$ScriptVersion &nbsp;&#x2022;&nbsp; $ScriptAuthor</div>
  </div>
</header>
<div class="meta-bar">
  <span><strong>Profile:</strong> Enterprise / Telco / Mobile Money</span>
  <span><strong>KB Entries:</strong> $($TelcoKB.Count)</span>
  <span><strong>Matches Found:</strong> $($ProductMatches.Count)</span>
  <span><strong>Unknown Processes:</strong> $($UnknownProcs.Count)</span>
</div>
$SysInfoBlock
<div class="stats">
$(
    $cats = $ProductMatches | Group-Object Category | Sort-Object Count -Desc
    foreach ($c in $cats) {
        "<div class='stat-card'><div class='num'>$($c.Count)</div><div class='lbl'>$($c.Name)</div></div>"
    }
    $critCount = @($ProductMatches | Where-Object { $_.RiskLevel -eq 'Critical' }).Count
    $highCount = @($ProductMatches | Where-Object { $_.RiskLevel -eq 'High' }).Count
    "<div class='stat-card critical'><div class='num'>$critCount</div><div class='lbl'>Critical</div></div>"
    "<div class='stat-card high'><div class='num'>$highCount</div><div class='lbl'>High</div></div>"
)
</div>

<div class="controls">
  <input type="text" id="searchInput" placeholder="&#128269; Search products, paths, processes..." oninput="filterTable()">
  <select id="catFilter" onchange="filterTable()">
    <option value="">All Categories</option>
$(
    $TelcoKB | Group-Object Category | Sort-Object Name | ForEach-Object {
        "<option value='$($_.Name)'>$($_.Name)</option>"
    }
)
  </select>
  <select id="riskFilter" onchange="filterTable()">
    <option value="">All Risk Levels</option>
    <option value="Critical">Critical</option>
    <option value="High">High</option>
    <option value="Medium">Medium</option>
    <option value="Low">Low</option>
  </select>
  <button class="btn" onclick="exportCSVClient()">&#x2B73; Export CSV</button>
</div>

<div class="main">
  <div class="section-title">&#9989; Matched Exclusions ($($ProductMatches.Count) products detected)</div>
  <table id="mainTable">
    <thead>
      <tr>
        <th style="width:80px">Risk</th>
        <th>Product / Match</th>
        <th>Category</th>
        <th>Exclude Paths</th>
        <th>Exclude Processes</th>
        <th>Extensions</th>
        <th>Notes</th>
      </tr>
    </thead>
    <tbody>
      $ProductRows
    </tbody>
  </table>

  <div class="section-title" style="margin-top:32px">&#x26A0;&#xFE0F; Unknown Non-System Processes (Review Manually)</div>
  <div class="warn-box">These processes were detected but did not match any KB entry. Review to determine whether additional S1 exclusions are needed.</div>
  <table>
    <thead><tr><th>Process Name</th><th>Executable Path</th><th>Command Line</th></tr></thead>
    <tbody>$UnknownRows</tbody>
  </table>
</div>

<footer>SentinelOne Exclusion Generator v$ScriptVersion &nbsp;&#x2022;&nbsp; $ScriptAuthor &nbsp;&#x2022;&nbsp; Not a substitute for vendor-specific tuning. Always validate exclusions against the SentinelOne console best-practice guidance.</footer>

<script>
function filterTable() {
  const search = document.getElementById('searchInput').value.toLowerCase();
  const cat    = document.getElementById('catFilter').value;
  const risk   = document.getElementById('riskFilter').value;
  document.querySelectorAll('#mainTable tbody tr.row-data').forEach(row => {
    const text   = row.textContent.toLowerCase();
    const rowCat = row.dataset.cat;
    const rowRisk= row.dataset.risk;
    const show = (!search || text.includes(search)) &&
                 (!cat    || rowCat === cat) &&
                 (!risk   || rowRisk === risk);
    row.classList.toggle('hidden', !show);
  });
}
function exportCSVClient() {
  const rows = [['Risk','Product','Category','MatchReason','ExcludePaths','ExcludeProcesses','Extensions','Notes']];
  document.querySelectorAll('#mainTable tbody tr.row-data:not(.hidden)').forEach(row => {
    const cells = row.querySelectorAll('td');
    rows.push([
      cells[0].textContent.trim(),
      cells[1].querySelector('strong').textContent.trim(),
      cells[2].textContent.trim(),
      cells[1].querySelector('small')?.textContent.trim() || '',
      Array.from(cells[3].querySelectorAll('code')).map(c=>c.textContent).join('|'),
      Array.from(cells[4].querySelectorAll('code')).map(c=>c.textContent).join('|'),
      Array.from(cells[5].querySelectorAll('code')).map(c=>c.textContent).join(' '),
      cells[6].textContent.trim()
    ]);
  });
  const csv = rows.map(r => r.map(v => '"'+String(v).replace(/"/g,'""')+'"').join(',')).join('\n');
  const a = document.createElement('a');
  a.href = 'data:text/csv;charset=utf-8,﻿' + encodeURIComponent(csv);
  a.download = 'S1_Exclusions_Filtered.csv';
  a.click();
}
</script>
</body>
</html>
"@

    $HTML | Out-File -FilePath $Path -Encoding UTF8 -ErrorAction Stop
    Write-Success "HTML report exported: $Path"
    } catch {
        Write-Fail "HTML export failed for $Path : $($_.Exception.Message)"
    }
}

# Writes a plain-text dump of the same data, sorted by risk and
# category. Extensions are dotted to match the CSV / JSON / HTML
# outputs (the v2.1 TXT format omitted the leading dot).
function Export-ExclusionTXT {
    [CmdletBinding()]
    param([array]$ProductMatches, [string]$Path)
    try {
        $lines = @()
        $lines += '=' * 78
        $lines += "  SENTINELONE EXCLUSION LIST  -  v$ScriptVersion"
        $lines += "  Author : $ScriptAuthor"
        $lines += "  Host   : $env:COMPUTERNAME"
        $lines += "  Date   : $(Get-Date -Format 'o')"
        $lines += '=' * 78

        foreach ($m in ($ProductMatches | Sort-Object RiskLevel, Category)) {
            $lines += ''
            $lines += "[$($m.RiskLevel.ToUpper())] $($m.ProductName) | $($m.Category)"
            $lines += "  Match: $($m.MatchReason)"
            if ($m.Notes) { $lines += "  Note : $($m.Notes)" }
            if ($m.ExcludePaths) {
                $lines += '  --- PATH EXCLUSIONS ---'
                foreach ($p in $m.ExcludePaths) { $lines += "    $(Expand-ExclusionPath $p)" }
            }
            if ($m.ExcludeProcs) {
                $lines += '  --- PROCESS EXCLUSIONS ---'
                foreach ($pr in $m.ExcludeProcs) { $lines += "    $pr" }
            }
            if ($m.ExcludeExts) {
                $lines += '  --- EXTENSION EXCLUSIONS ---'
                $lines += '    ' + (($m.ExcludeExts | ForEach-Object { ".$_" }) -join ', ')
            }
            $lines += '-' * 78
        }
        $lines | Out-File -FilePath $Path -Encoding UTF8 -ErrorAction Stop
        Write-Success "TXT exported: $Path"
    } catch {
        Write-Fail "TXT export failed for $Path : $($_.Exception.Message)"
    }
}

# ============================================================
#  MAIN EXECUTION
# ============================================================

Write-Host ''
Write-Host '  +==========================================================+' -ForegroundColor Cyan
Write-Host "  |  S1-ExclusionGenerator v$ScriptVersion                              |" -ForegroundColor Cyan
Write-Host "  |  Author: $ScriptAuthor                              |" -ForegroundColor Cyan
Write-Host '  +==========================================================+' -ForegroundColor Cyan
Write-Host ''

# Warn (but do not block) when the script is not elevated. The
# inventory will be partial in this case -- some process paths and the
# HKU registry hive will be inaccessible.
if (-not (Test-IsAdmin)) {
    Write-Warn 'Not running as Administrator. Process paths for other security contexts and parts of HKU will be inaccessible -- inventory will be incomplete. Re-run from an elevated PowerShell session for full coverage.'
}

# ---- Per-host scan (always local; ComputerName is purely a label) ----
$labelHost = if ([string]::IsNullOrWhiteSpace($ComputerName)) { $env:COMPUTERNAME } else { $ComputerName }

Write-Host ''
Write-Host '  ------------------------------------------' -ForegroundColor DarkCyan
Write-Host "  TARGET: $labelHost" -ForegroundColor White
Write-Host '  ------------------------------------------' -ForegroundColor DarkCyan

$SysInfo = Get-SystemInfo
if ($SysInfo) { Write-Info "OS: $($SysInfo.OSName) | Arch: $($SysInfo.Architecture)" }

$Installed = Get-InstalledSoftware
$Services  = Get-RunningServices
$Processes = Get-RunningProcesses

$result   = Find-ExclusionMatches -InstalledSoftware $Installed `
                                  -RunningServices  $Services  `
                                  -RunningProcesses $Processes
$Matched  = @($result.Matches)
$Unknown  = @($result.UnknownProcs)

# Build a filesystem-safe filename prefix from the (possibly weird)
# hostname value so a string like 'DOMAIN\HOST' does not blow up the
# Export-* calls with IllegalCharsInPath.
$SafeHost = ConvertTo-SafeFileName $labelHost
$Prefix   = Join-Path $OutputPath "${ReportBaseName}_${SafeHost}"

Export-ExclusionCSV  -ProductMatches $Matched -Path "${Prefix}.csv"
Export-ExclusionJSON -ProductMatches $Matched -Path "${Prefix}.json"
Export-ExclusionTXT  -ProductMatches $Matched -Path "${Prefix}.txt"
Export-ExclusionHTML -ProductMatches $Matched -UnknownProcs $Unknown -SysInfo $SysInfo -Path "${Prefix}.html"

Write-Success "Scan complete for $labelHost  --  $(@($Matched).Count) exclusion groups generated"

Write-Host ''
Write-Host "  [OK] Reports saved to: $OutputPath" -ForegroundColor Green
Write-Host '  [OK] Open the .html file for the interactive report.' -ForegroundColor Green
Write-Host ''
Write-Host '  NOTE: Always validate exclusions against the SentinelOne console' -ForegroundColor Yellow
Write-Host '        best-practice guidance. Apply exclusions at the Policy level,' -ForegroundColor Yellow
Write-Host '        never globally across the tenant.' -ForegroundColor Yellow
Write-Host ''

if ($script:Failures -gt 0) {
    Write-Warn "Completed with $script:Failures non-fatal error(s)."
    exit 1
}
exit 0
