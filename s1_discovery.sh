#!/usr/bin/env bash
# =============================================================================
#  s1_discovery.sh
#
#  SentinelOne EDR -- exclusion discovery for Linux endpoints.
#
#  Detects running services and installed components (web servers, databases,
#  container runtimes, backup agents, message brokers, ...) and writes a
#  SentinelOne-ready exclusion list to /tmp by default. The output covers
#  path, process, and file-extension exclusions, plus a section of warnings
#  flagging trade-offs the operator should review before importing into the
#  S1 console.
#
#  Author  : Alaa G. Sukarieh
#  Version : 1.0
#  License : MIT
#  Tested  : Bash 4+ on Debian / Ubuntu / RHEL / CentOS / Rocky / Alma /
#            Oracle Linux / SUSE.
#  Run As  : root (some inventory steps -- /proc/<pid>/environ, sqlplus as
#            sysdba, /etc/oraInst.loc, swap listing -- require it). The
#            script refuses to run as a non-root user.
#
#  Usage:
#     sudo bash s1_discovery.sh [-o /path/to/output.txt] [-h|--help]
#
#  Exit codes:
#     0   discovery completed
#     1   not running as root, or invalid usage
# =============================================================================
set -uo pipefail

# ----- argument parsing ------------------------------------------------------
CUSTOM_OUT=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output)
            CUSTOM_OUT="${2:-}"
            if [[ -z "$CUSTOM_OUT" ]]; then
                echo "ERROR: -o requires a file path." >&2
                exit 1
            fi
            shift 2
            ;;
        -h|--help)
            sed -n '2,29p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            echo "Run with --help for usage." >&2
            exit 1
            ;;
    esac
done

[[ $EUID -ne 0 ]] && { echo "ERROR: Run as root or via sudo."; exit 1; }

# ----- Setup -----------------------------------------------------------------
# Sanitize hostname so the auto-generated filename never trips on weird DNS
# names (DOMAIN\HOST on AD-joined boxes, IPv6 literals, FQDNs with reserved
# characters, etc.).
RAW_HOST="$(hostname -s 2>/dev/null || echo UNKNOWN)"
SAFE_HOST="$(echo "$RAW_HOST" | tr -c 'A-Za-z0-9._-' '_')"
[[ -z "$SAFE_HOST" ]] && SAFE_HOST="UNKNOWN"

if [[ -n "$CUSTOM_OUT" ]]; then
    OUTFILE="$CUSTOM_OUT"
else
    OUTFILE="/tmp/s1_exclusions_${SAFE_HOST}_$(date +%Y%m%d_%H%M%S).txt"
fi

declare -a PATH_EXCL=()
declare -a PROC_EXCL=()
declare -a EXT_EXCL=()
declare -a DETECTED=()
declare -a WARNINGS=()

add_path() { [[ -n "${1:-}" ]] && PATH_EXCL+=("$1"); }
add_proc() { [[ -n "${1:-}" ]] && PROC_EXCL+=("$1"); }
add_ext()  { [[ -n "${1:-}" ]] && EXT_EXCL+=("$1");  }
note()     { WARNINGS+=("$*"); echo "  [!] $*"; }

is_running() { pgrep -x  "$1" &>/dev/null; }
has_proc()   { pgrep -f  "$1" &>/dev/null; }
svc_on()     { systemctl is-active --quiet "$1" 2>/dev/null || systemctl is-enabled --quiet "$1" 2>/dev/null; }
has_cmd()    { command -v "$1" &>/dev/null; }
found()      { echo "  [+] $*"; DETECTED+=("$*"); }

# ─── OS info ──────────────────────────────────────────────────────────────────
OS_PRETTY="Unknown"
[[ -f /etc/os-release ]] && { source /etc/os-release; OS_PRETTY="${PRETTY_NAME:-Unknown}"; }

echo "======================================================"
echo "  S1 Exclusion Discovery"
echo "  Host : $(hostname -f)"
echo "  OS   : $OS_PRETTY"
echo "  Date : $(date)"
echo "======================================================"
echo "Scanning services..."
echo

# =============================================================================
# DETECTORS
# =============================================================================

# ── Apache ─────────────────────────────────────────────────────────────────────────
if is_running apache2 || is_running httpd || svc_on apache2 || svc_on httpd; then
    found "Apache HTTPD"
    add_proc "/usr/sbin/apache2"
    add_proc "/usr/sbin/httpd"
    add_path "/etc/apache2"
    add_path "/etc/httpd"
    add_path "/var/log/apache2"
    add_path "/var/log/httpd"
    add_path "/var/run/apache2"
    add_path "/var/run/httpd"
    add_path "/var/cache/apache2"
    # Discover DocumentRoot directories from config
    while IFS= read -r dr; do
        add_path "$dr"
    done < <(grep -rh '^\s*DocumentRoot' /etc/apache2/ /etc/httpd/ 2>/dev/null \
             | awk '{print $2}' | tr -d '"' | sort -u)
fi

# ── Nginx ──────────────────────────────────────────────────────────────────────────
if is_running nginx || svc_on nginx; then
    found "Nginx"
    add_proc "/usr/sbin/nginx"
    add_path "/etc/nginx"
    add_path "/var/log/nginx"
    add_path "/var/cache/nginx"
    add_path "/var/run/nginx.pid"
    add_path "/usr/share/nginx"
    while IFS= read -r r; do
        add_path "$r"
    done < <(grep -rh '^\s*root\s' /etc/nginx/ 2>/dev/null \
             | awk '{print $2}' | tr -d ';' | sort -u)
fi

# ── PHP-FPM ─────────────────────────────────────────────────────────────────────────
if is_running php-fpm || has_proc "php.*fpm" || svc_on php-fpm; then
    found "PHP-FPM"
    add_proc "php-fpm"
    add_proc "php"
    add_path "/etc/php"
    add_path "/var/run/php"
    add_path "/var/lib/php"
    add_path "/tmp/sess_*"
    add_path "/tmp/php*"
    add_ext  ".php"
fi

# ── Tomcat / Java app server ─────────────────────────────────────────────────────────────
if has_proc "catalina" || has_proc "tomcat" || svc_on tomcat || svc_on tomcat9; then
    found "Tomcat / Java App Server"
    add_proc "java"
    # Find CATALINA_HOME from running process
    CH=$(ps aux 2>/dev/null | grep -oP 'catalina\.home=\K[^\s]+' | head -1 || true)
    [[ -z "$CH" ]] && CH="/opt/tomcat"
    for d in "$CH" /usr/share/tomcat* /var/lib/tomcat*; do
        [[ -d "$d" ]] && add_path "$d"
    done
    add_path "/var/log/tomcat*"
    add_path "/tmp/tomcat*"
    add_path "/tmp/hsperfdata_*"
    add_path "/tmp/hs_err_pid*"
    add_ext  ".jar"
    add_ext  ".war"
    add_ext  ".class"
    add_ext  ".jsa"
    add_ext  ".hprof"
fi

# ── MySQL / MariaDB ─────────────────────────────────────────────────────────────────────
if is_running mysqld || is_running mariadbd || svc_on mysql || svc_on mariadb; then
    found "MySQL / MariaDB"
    add_proc "mysqld"
    add_proc "mariadbd"
    # Read datadir from my.cnf (authoritative)
    MYSQL_DATADIR=$(my_print_defaults --mysqld 2>/dev/null | grep datadir | tail -1 | cut -d= -f2 || true)
    [[ -z "$MYSQL_DATADIR" ]] && MYSQL_DATADIR="/var/lib/mysql"
    add_path "$MYSQL_DATADIR"
    add_path "/var/log/mysql"
    add_path "/var/log/mariadb"
    add_path "/var/run/mysqld"
    add_path "/tmp/mysql*"
    add_path "/tmp/#sql*"
    add_ext  ".ibd"
    add_ext  ".frm"
    add_ext  ".MYD"
    add_ext  ".MYI"
fi

# ── PostgreSQL ───────────────────────────────────────────────────────────────────────
if is_running postgres || svc_on postgresql; then
    found "PostgreSQL"
    add_proc "postgres"
    # Resolve PGDATA from running process
    PGDATA=$(ps aux 2>/dev/null | grep "[p]ostgres" | grep -oP '\-D\s+\K\S+' | head -1 || true)
    if [[ -z "$PGDATA" ]] && has_cmd pg_lsclusters; then
        PGDATA=$(pg_lsclusters --no-header 2>/dev/null | awk '{print $6}' | head -1 || true)
    fi
    [[ -z "$PGDATA" ]] && PGDATA="/var/lib/postgresql"
    add_path "$PGDATA"
    add_path "/var/lib/postgresql"
    add_path "/var/log/postgresql"
    add_path "/var/run/postgresql"
    add_path "/tmp/.s.PGSQL.*"
fi

# ── Oracle Database ─────────────────────────────────────────────────────────────────────
if has_proc "ora_" || is_running oracle || id oracle &>/dev/null 2>&1; then
    found "Oracle Database"
    add_proc "oracle"
    add_proc "tnslsnr"

    # Resolve ORACLE_HOME: try running process env first, then oratab, then find
    ORACLE_HOME=""
    ORA_PID=$(pgrep -x oracle 2>/dev/null | head -1 || true)
    if [[ -n "$ORA_PID" ]]; then
        ORACLE_HOME=$(cat /proc/"$ORA_PID"/environ 2>/dev/null \
                      | tr '\0' '\n' | grep ^ORACLE_HOME= | cut -d= -f2 || true)
    fi
    if [[ -z "$ORACLE_HOME" ]]; then
        ORACLE_HOME=$(grep -v '^#\|^$' /etc/oratab 2>/dev/null \
                      | grep -v '^+' | head -1 | cut -d: -f2 || true)
    fi
    if [[ -z "$ORACLE_HOME" ]]; then
        ORACLE_HOME=$(find /u01 /opt/oracle /home/oracle -name "sqlplus" \
                      -maxdepth 8 2>/dev/null | head -1 | sed 's|/bin/sqlplus||' || true)
    fi
    [[ -z "$ORACLE_HOME" ]] && ORACLE_HOME="/u01/app/oracle/product"

    # Derive ORACLE_BASE from ORACLE_HOME
    ORACLE_BASE=$(echo "$ORACLE_HOME" | grep -oP '^.+?(?=/product)' 2>/dev/null \
                  || echo "/u01/app/oracle")

    # oraInventory location
    ORA_INV="/u01/app/oraInventory"
    if [[ -f /etc/oraInst.loc ]]; then
        ORA_INV=$(grep inventory_loc /etc/oraInst.loc 2>/dev/null | cut -d= -f2 || echo "$ORA_INV")
    fi

    add_path "$ORACLE_HOME"
    add_path "$ORACLE_BASE/diag"
    add_path "$ORACLE_BASE/admin"
    add_path "$ORACLE_BASE/fast_recovery_area"
    add_path "$ORA_INV"
    add_path "/etc/oratab"
    add_path "/etc/oraInst.loc"
    add_path "/tmp/oracle*"
    add_path "/var/tmp/.oracle"
    add_path "/tmp/.oracle"

    # ── Auto-query each running SID via sqlplus ────────────────────────────
    SQLPLUS="$ORACLE_HOME/bin/sqlplus"
    if [[ -x "$SQLPLUS" ]]; then
        while IFS=: read -r ORA_SID ORA_OH ORA_FLAG; do
            # Skip comments, blank lines, ASM instances, and disabled entries
            [[ -z "$ORA_SID" || "$ORA_SID" =~ ^# ]] && continue
            [[ "$ORA_SID" =~ ^\+ ]] && continue          # ASM
            [[ "$ORA_FLAG" == "N" ]] && continue          # not auto-started

            echo "  [~] Querying Oracle SID: $ORA_SID"

            # Run sqlplus as the oracle OS user with correct environment
            SQL_OUT=$(su -s /bin/bash oracle -c "
                export ORACLE_HOME='$ORACLE_HOME'
                export ORACLE_SID='$ORA_SID'
                export PATH=\$ORACLE_HOME/bin:\$PATH
                export LD_LIBRARY_PATH=\$ORACLE_HOME/lib:\$LD_LIBRARY_PATH
                '$SQLPLUS' -s / as sysdba << 'ENDSQL'
WHENEVER SQLERROR CONTINUE
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF TRIMSPOOL ON NEWPAGE NONE
-- Datafile directories
SELECT DISTINCT regexp_replace(name, '[^/]+\$', '') FROM v\$datafile;
-- Redo log directories
SELECT DISTINCT regexp_replace(member, '[^/]+\$', '') FROM v\$logfile;
-- Control file directories
SELECT DISTINCT regexp_replace(name, '[^/]+\$', '') FROM v\$controlfile;
-- Diagnostic / dump destinations
SELECT DISTINCT value FROM v\$parameter
  WHERE name IN ('audit_file_dest','core_dump_dest',
                 'background_dump_dest','user_dump_dest',
                 'db_recovery_file_dest');
EXIT;
ENDSQL
" 2>/dev/null || true)

            while IFS= read -r dir; do
                dir=$(echo "$dir" | xargs 2>/dev/null || true)
                [[ -z "$dir" ]] && continue
                [[ "$dir" =~ "no rows" ]] && continue
                [[ "$dir" =~ "ORA-" ]] && continue
                echo "       → $dir"
                add_path "$dir"
            done <<< "$SQL_OUT"

        done < <(grep -v '^#\|^$' /etc/oratab 2>/dev/null || true)
    else
        note "Oracle: sqlplus not found at $SQLPLUS — add datafile/redo/control paths manually"
        note "  Run: SELECT name FROM v\$datafile; SELECT member FROM v\$logfile;"
    fi

    # ASM raw device paths
    if has_proc "asm_" || has_proc "ocssd"; then
        found "Oracle ASM"
        add_path "/dev/asm*"
        add_path "/dev/oracleasm"
        add_path "/etc/sysconfig/oracleasm"
    fi

    add_ext ".dbf"    # datafiles / tablespaces
    add_ext ".ctl"    # control files
    add_ext ".arc"    # archived redo logs
    add_ext ".bkp"    # RMAN backup pieces
    add_ext ".dmp"    # Data Pump export files
    add_ext ".trc"    # trace files
    add_ext ".trm"    # trace index files
    add_ext ".aud"    # audit files
fi

# ── Oracle TNS Listener ─────────────────────────────────────────────────────────────────────
if is_running tnslsnr; then
    add_proc "tnslsnr"
    add_path "/tmp/.oracle"
    add_path "/var/tmp/.oracle"
fi

# ── MongoDB ─────────────────────────────────────────────────────────────────────────
if is_running mongod || svc_on mongod; then
    found "MongoDB"
    add_proc "mongod"
    MONGO_DIR=$(grep -oP '(?<=dbPath:\s)\S+' /etc/mongod.conf 2>/dev/null \
                || echo "/var/lib/mongodb")
    add_path "$MONGO_DIR"
    add_path "/var/log/mongodb"
    add_path "/var/run/mongodb"
    add_ext  ".wt"
fi

# ── Redis ──────────────────────────────────────────────────────────────────────────
if is_running redis-server || svc_on redis || svc_on redis-server; then
    found "Redis"
    add_proc "redis-server"
    REDIS_DIR="/var/lib/redis"
    for CF in /etc/redis/redis.conf /etc/redis.conf; do
        if [[ -f "$CF" ]]; then
            D=$(grep -oP '(?<=^dir\s)\S+' "$CF" 2>/dev/null || true)
            [[ -n "$D" ]] && REDIS_DIR="$D"
            break
        fi
    done
    add_path "$REDIS_DIR"
    add_path "/var/log/redis"
    add_path "/var/run/redis"
    add_ext  ".rdb"
    add_ext  ".aof"
fi

# ── Elasticsearch ───────────────────────────────────────────────────────────────────────
if has_proc "elasticsearch" || svc_on elasticsearch; then
    found "Elasticsearch"
    add_proc "java"
    add_path "/var/lib/elasticsearch"
    add_path "/etc/elasticsearch"
    add_path "/var/log/elasticsearch"
    add_path "/tmp/elasticsearch*"
    add_path "/tmp/hsperfdata_elasticsearch"
    add_ext  ".cfs"
    add_ext  ".si"
fi

# ── Cassandra ────────────────────────────────────────────────────────────────────────
if has_proc "cassandra" || svc_on cassandra; then
    found "Apache Cassandra"
    add_proc "java"
    add_path "/var/lib/cassandra"
    add_path "/var/log/cassandra"
    add_path "/etc/cassandra"
fi

# ── RabbitMQ ───────────────────────────────────────────────────────────────────────
if has_proc "rabbitmq" || is_running beam.smp || svc_on rabbitmq-server; then
    found "RabbitMQ"
    add_proc "beam.smp"
    add_proc "epmd"
    add_path "/var/lib/rabbitmq"
    add_path "/var/log/rabbitmq"
    add_path "/etc/rabbitmq"
fi

# ── HAProxy ───────────────────────────────────────────────────────────────────────
if is_running haproxy || svc_on haproxy; then
    found "HAProxy"
    add_proc "/usr/sbin/haproxy"
    add_path "/etc/haproxy"
    add_path "/var/log/haproxy"
    add_path "/var/run/haproxy"
fi

# ── Docker ───────────────────────────────────────────────────────────────────────
if is_running dockerd || svc_on docker; then
    found "Docker"
    add_proc "dockerd"
    add_proc "containerd"
    add_proc "containerd-shim"
    DOCKER_ROOT="/var/lib/docker"
    has_cmd docker && DOCKER_ROOT=$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || echo "$DOCKER_ROOT")
    add_path "$DOCKER_ROOT/overlay2"
    add_path "$DOCKER_ROOT/containers"
    add_path "$DOCKER_ROOT/volumes"
    add_path "/var/run/docker.sock"
    add_path "/run/containerd"
    note "Docker: overlay2 exclusion is broad — review per-container risk"
fi

# ── Kubernetes ───────────────────────────────────────────────────────────────────────
if is_running kubelet || svc_on kubelet; then
    found "Kubernetes (kubelet)"
    add_proc "kubelet"
    add_proc "kube-proxy"
    add_path "/var/lib/kubelet"
    add_path "/var/lib/cni"
    add_path "/opt/cni"
    add_path "/run/containerd"
    add_path "/etc/kubernetes"
    add_path "/var/log/pods"
    add_path "/var/log/containers"
fi

# ── NFS server ───────────────────────────────────────────────────────────────────────
if is_running nfsd || svc_on nfs-server || svc_on nfs-kernel-server; then
    found "NFS Server"
    add_proc "nfsd"
    add_proc "rpc.mountd"
    add_path "/proc/fs/nfsd"
    add_path "/var/lib/nfs"
fi

# ── NFS / CIFS mounts (auto-discover) ──────────────────────────────────────────────────────────
while IFS= read -r mnt; do
    [[ -n "$mnt" ]] && { echo "  [+] Remote mount: $mnt"; add_path "$mnt"; }
done < <(mount 2>/dev/null | grep -E '\s(nfs|nfs4|cifs|smbfs)\s' | awk '{print $3}' || true)

# ── Veeam Agent ───────────────────────────────────────────────────────────────────────
if has_proc "VeeamAgent" || svc_on veeam 2>/dev/null; then
    found "Veeam Agent for Linux"
    add_proc "VeeamAgent"
    add_path "/var/lib/veeam"
    add_path "/tmp/Veeam*"
    add_ext  ".vbk"
    add_ext  ".vib"
    add_ext  ".vrb"
fi

# ── Commvault ────────────────────────────────────────────────────────────────────────
if has_proc "^cvd$" || [[ -d /opt/commvault ]]; then
    found "Commvault"
    add_proc "cvd"
    add_proc "cvfwd"
    add_proc "cvlaunchd"
    add_path "/opt/commvault"
    add_path "/var/log/commvault"
fi

# ── Bacula ───────────────────────────────────────────────────────────────────────
if is_running bacula-fd || svc_on bacula-fd 2>/dev/null; then
    found "Bacula File Daemon"
    add_proc "bacula-fd"
    add_path "/var/lib/bacula"
    add_path "/var/log/bacula"
fi

# ── Universal OS-level paths (always include) ──────────────────────────────────────────────────────
# Pseudo-filesystems and runtime sockets -- safe to exclude (the kernel
# generates this content; scanning it produces phantom matches and wastes
# I/O without improving security).
add_path "/proc"
add_path "/sys"
add_path "/dev"
add_path "/run"
add_path "/run/systemd"

# Package manager caches / state -- noisy during updates, low-value to scan.
add_path "/var/cache/apt"
add_path "/var/cache/yum"
add_path "/var/cache/dnf"
add_path "/var/lib/rpm"
add_path "/var/lib/dpkg"

# Crash dumps -- excluding hides post-exploit forensic data. Operators who
# value crash-driven detections may want to remove these two before applying.
add_path "/var/crash"
add_path "/var/core"

# /tmp and /var/tmp are REAL filesystems on every distro -- they are also
# the most common drop locations for webshells, reverse shells, and
# exploit payloads. Excluding them blinds the agent to a large class of
# attacker behaviour. Still adding them by default because most legitimate
# applications generate enough noise here to make the trade-off worthwhile,
# but the operator must see the warning and decide.
add_path "/tmp"
add_path "/var/tmp"
note "Universal: /tmp and /var/tmp are excluded by default. These are common malware-drop locations. Consider removing them from the path list before importing, and rely on application-specific tmp subpaths (e.g. /tmp/sess_*, /tmp/mysql*) added by the detectors above."

# Swap files/partitions
while IFS= read -r swp; do
    [[ -n "$swp" ]] && add_path "$swp"
done < <(swapon --show=NAME --noheadings 2>/dev/null || true)

# =============================================================================
# DEDUPLICATE
# =============================================================================
# Guard each mapfile with a length check so empty arrays don't trip
# `set -u`. The previous form used the "${arr[@]+"${arr[@]}"}" idiom which
# is correct in bash but fragile to round-trip through JSON encoders.
if [[ ${#PATH_EXCL[@]} -gt 0 ]]; then
    mapfile -t PATH_EXCL < <(printf '%s\n' "${PATH_EXCL[@]}" | sort -u | grep -v '^$')
fi
if [[ ${#PROC_EXCL[@]} -gt 0 ]]; then
    mapfile -t PROC_EXCL < <(printf '%s\n' "${PROC_EXCL[@]}" | sort -u | grep -v '^$')
fi
if [[ ${#EXT_EXCL[@]}  -gt 0 ]]; then
    mapfile -t EXT_EXCL  < <(printf '%s\n' "${EXT_EXCL[@]}"  | sort -u | grep -v '^$')
fi

# =============================================================================
# WRITE OUTPUT FILE
# =============================================================================
{
cat << HEADER
=============================================================================
  SentinelOne EDR -- Recommended Exclusions
  Host      : $(hostname -f)
  OS        : $OS_PRETTY
  Kernel    : $(uname -r)
  Generated : $(date)
  Generator : s1_discovery.sh v1.0 (Alaa G. Sukarieh)
  Services  : $(if [[ ${#DETECTED[@]} -gt 0 ]]; then IFS=", "; echo "${DETECTED[*]}"; fi)
=============================================================================

SECTION 1 — PATH / FOLDER EXCLUSIONS
  Apply in: S1 Console → Exclusions → Path
  Tip: Use recursive (include subfolders) for database data directories.
-----------------------------------------------------------------------------
$(printf '  %s\n' "${PATH_EXCL[@]}")

SECTION 2 — PROCESS EXCLUSIONS
  Apply in: S1 Console → Exclusions → Process
-----------------------------------------------------------------------------
$(printf '  %s\n' "${PROC_EXCL[@]}")

SECTION 3 — FILE EXTENSION EXCLUSIONS
  Apply in: S1 Console → Exclusions → Extension
  *** IMPORTANT: Scope extension exclusions to the specific path above,
      never apply globally — this avoids blind spots for malware. ***
-----------------------------------------------------------------------------
$(printf '  %s\n' "${EXT_EXCL[@]}")

SECTION 4 — WARNINGS / MANUAL ACTIONS
-----------------------------------------------------------------------------
HEADER

if [[ ${#WARNINGS[@]} -eq 0 ]]; then
    echo "  None."
else
    printf '  [!] %s\n' "${WARNINGS[@]}"
fi

cat << FOOTER

=============================================================================
  NEXT STEPS
  1. Review all paths — remove entries that don't exist on this host.
  2. For Oracle: confirm paths with:
       SELECT name FROM v\$datafile;
       SELECT member FROM v\$logfile;
       SELECT name FROM v\$controlfile;
  3. For NFS: run  mount | grep nfs  to catch any missed mounts.
  4. Import into S1 via Console or API (/web/api/v2.1/exclusions).
  5. After S1 install, validate with Deep Visibility that no legitimate
     DB or web I/O is triggering detections.
=============================================================================
FOOTER
} > "$OUTFILE"

# =============================================================================
# CONSOLE SUMMARY
# =============================================================================
echo
echo "======================================================"
echo "  Done."
echo "  Services : ${#DETECTED[@]}  ($(if [[ ${#DETECTED[@]} -gt 0 ]]; then IFS=", "; echo "${DETECTED[*]}"; fi) )"
echo "  Paths    : ${#PATH_EXCL[@]}"
echo "  Processes: ${#PROC_EXCL[@]}"
echo "  Extensions: ${#EXT_EXCL[@]}"
if [[ ${#WARNINGS[@]} -gt 0 ]]; then
    echo
    for w in "${WARNINGS[@]}"; do echo "  [!] $w"; done
fi
echo
echo "  Output: $OUTFILE"
echo "======================================================"
