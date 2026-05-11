#!/usr/bin/env bash
# Dragon Vault — Quarterly Restore Drill
# REQ-056: Restore newest .bak to DragonVault_RestoreTest,
#          verify row counts on key tables, then drop the test database.
#
# Manual invocation (quarterly):
#   sudo -u YOUR-USERNAME /var/opt/dragonvault/restore-drill.sh
#
# For CI / cron, ensure SQL_PASSWORD is set in the environment.
set -euo pipefail

# === Configuration (override via env vars) ===
BACKUP_DIR="${BACKUP_DIR:-"/var/opt/dragonvault/backups"}"
DB_NAME="${DB_NAME:-"DragonVault"}"
TEST_DB="${TEST_DB:-"DragonVault_RestoreTest"}"

SQL_SERVER="${SQL_SERVER:-"."}"
SQL_USER="${SQL_USER:-"sa"}"
SQL_PASSWORD="${SQL_PASSWORD:-}"

# Docker exec path mapping (same as backup-db.sh)
SQLCMD_INTERNAL_PATH="${SQLCMD_INTERNAL_PATH:-"/var/opt/mssql/backups"}"
SQL_CONTAINER_NAMES="${SQL_CONTAINER:-mssql sqlserver mssql-server mssql2022}"
SQLCMD_BIN="${SQLCMD_BIN:-"/opt/mssql-tools18/bin/sqlcmd"}"
# =============================================

echo "=== Dragon Vault — Restore Drill ==="
echo "Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Source DB:         $DB_NAME"
echo "Test restore to:   $TEST_DB"
echo "Backup directory:  $BACKUP_DIR"
echo ""

# ---- Step 0: Pre-flight checks ----
if [ ! -d "$BACKUP_DIR" ]; then
    echo "FATAL: Backup directory $BACKUP_DIR does not exist."
    exit 1
fi

if [ -z "$SQL_PASSWORD" ]; then
    echo "FATAL: SQL_PASSWORD is not set."
    exit 1
fi

# ---- Step 1: Discover SQL Server (same logic as backup-db.sh) ----
SQLCMD_CMD=""
SQLMODE=""

for cname in $SQL_CONTAINER_NAMES; do
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -qFx "$cname"; then
        echo "[1/7] SQL Server container found: $cname"
        SQLCMD_CMD="docker exec $cname $SQLCMD_BIN"
        SQLMODE="docker"
        break
    fi
done

if [ -z "$SQLMODE" ]; then
    if command -v sqlcmd &>/dev/null; then
        echo "[1/7] No SQL container found. Using host sqlcmd."
        SQLCMD_CMD="sqlcmd"
        SQLMODE="host"
        SQLCMD_INTERNAL_PATH="$BACKUP_DIR"
    else
        echo "FATAL: No SQL Server reachable (docker or host)."
        exit 1
    fi
fi

SQLCMD_ARGS="-S $SQL_SERVER -U $SQL_USER -P $SQL_PASSWORD -C -b"

# ---- Step 2: Find the newest .bak file ----
echo "[2/7] Finding newest backup..."
NEWEST_BAK=$(find "$BACKUP_DIR" -maxdepth 1 -name '*.bak' -printf '%T@\t%p\n' 2>/dev/null | sort -t$'\t' -k1 -rn | head -1 | cut -f2-)

if [ -z "$NEWEST_BAK" ]; then
    echo "FATAL: No .bak files found in $BACKUP_DIR."
    exit 1
fi

BAK_FILENAME=$(basename "$NEWEST_BAK")
echo "  Found: $NEWEST_BAK"

# Map host path to internal container path for docker mode
if [ "$SQLMODE" = "docker" ]; then
    RESTORE_PATH="${SQLCMD_INTERNAL_PATH}/${BAK_FILENAME}"
else
    RESTORE_PATH="$NEWEST_BAK"
fi

# ---- Step 3: Get logical file names from the backup ----
echo "[3/7] Retrieving logical file names from backup..."
echo "  Backup path (SQL Server view): $RESTORE_PATH"

FILELISTONLY_SQL="
SET NOCOUNT ON;
RESTORE FILELISTONLY FROM DISK = N'${RESTORE_PATH}';
"

# Run FILELISTONLY and extract logical names
# The output format is tabular; we need the LogicalName column (first column)
FILELIST_OUTPUT=$($SQLCMD_CMD $SQLCMD_ARGS -Q "$FILELISTONLY_SQL" -s"|" -W 2>&1)

# Parse: skip header lines, extract first pipe-delimited field
LOGICAL_NAMES=()
while IFS='|' read -r -a line; do
    # Skip header row (LogicalName) and separator rows (---)
    name="${line[0]}"
    if [ -n "$name" ] && [ "$name" != "LogicalName" ] && [[ "$name" != -* ]]; then
        LOGICAL_NAMES+=("$name")
    fi
done <<< "$FILELIST_OUTPUT"

if [ ${#LOGICAL_NAMES[@]} -eq 0 ]; then
    echo "FATAL: Could not parse logical file names from backup."
    echo "Raw output:"
    echo "$FILELIST_OUTPUT"
    exit 1
fi

echo "  Logical files found: ${LOGICAL_NAMES[*]}"

# Build MOVE clauses. For simplicity, use default paths.
# Production data files usually live at:
#   /var/opt/mssql/data/ (Docker) or default SQL Server data path
MOVE_CLAUSES=""
for lname in "${LOGICAL_NAMES[@]}"; do
    # Determine if it's a data file (.mdf/.ndf) or log file (.ldf)
    if echo "$lname" | grep -qi 'log'; then
        MOVE_CLAUSES="$MOVE_CLAUSES MOVE '$lname' TO '${SQLCMD_INTERNAL_PATH}/${TEST_DB}_log.ldf',"
    else
        MOVE_CLAUSES="$MOVE_CLAUSES MOVE '$lname' TO '${SQLCMD_INTERNAL_PATH}/${TEST_DB}.mdf',"
    fi
done
# Remove trailing comma
MOVE_CLAUSES="${MOVE_CLAUSES%,}"

# ---- Step 4: Restore the database ----
echo "[4/7] Restoring to database [$TEST_DB]..."

# First drop the test database if it already exists
$SQLCMD_CMD $SQLCMD_ARGS -Q "
IF DB_ID('$TEST_DB') IS NOT NULL
BEGIN
    ALTER DATABASE [$TEST_DB] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE [$TEST_DB];
    PRINT 'Dropped existing [$TEST_DB]';
END
" 2>&1 || echo "  (No existing test DB to drop)"

# Now restore
RESTORE_SQL="
RESTORE DATABASE [$TEST_DB]
FROM DISK = N'${RESTORE_PATH}'
WITH REPLACE, ${MOVE_CLAUSES}, STATS=10;
"

echo "  Running RESTORE DATABASE..."
echo "  (MOVE clauses generated from FILELISTONLY = ${MOVE_CLAUSES:0:120}...)"
if ! $SQLCMD_CMD $SQLCMD_ARGS -Q "$RESTORE_SQL"; then
    echo "FATAL: RESTORE DATABASE command failed."
    echo "  The MOVE paths may need adjustment. Check SQL Server file permissions."
    exit 1
fi

echo "  Restore completed successfully."

# ---- Step 5: Row-count verification ----
echo "[5/7] Verifying row counts on key tables..."

verify_row_count() {
    local table="$1"
    local sql="SELECT COUNT_BIG(1) AS cnt FROM [$TEST_DB].$table;"
    local count
    count=$($SQLCMD_CMD $SQLCMD_ARGS -Q "$sql" -h-1 -W 2>/dev/null | grep -E '^[0-9]+$' | head -1)
    if [ -z "$count" ]; then
        echo "  FAILED to query $table (table may not exist)"
        return 1
    fi
    echo "  $table: $count rows"
}

FAILURES=0

# Application tables
verify_row_count "dbo.AspNetUsers"     || FAILURES=$((FAILURES + 1))
verify_row_count "dbo.VaultEntries"    || FAILURES=$((FAILURES + 1))
verify_row_count "dbo.EntryFields"     || FAILURES=$((FAILURES + 1))
verify_row_count "dbo.WebAuthnCredentials" || FAILURES=$((FAILURES + 1))
verify_row_count "dbo.ErrorLog"        || FAILURES=$((FAILURES + 1))

# Identity tables (should always exist)
verify_row_count "dbo.AspNetUserLogins"    || FAILURES=$((FAILURES + 1))
verify_row_count "dbo.AspNetUserTokens"    || FAILURES=$((FAILURES + 1))
verify_row_count "dbo.AspNetRoles"         || FAILURES=$((FAILURES + 1))
verify_row_count "dbo.AspNetRoleClaims"    || FAILURES=$((FAILURES + 1))
verify_row_count "dbo.AspNetUserClaims"    || FAILURES=$((FAILURES + 1))

# Additional structural checks
echo "  ---"
# Verify VaultEntries -> EntryFields FK relationship holds
echo "  Checking FK VaultEntries -> EntryFields..."
FK_SQL="
SELECT COUNT_BIG(1) AS orphan_count
FROM [$TEST_DB].dbo.EntryFields ef
LEFT JOIN [$TEST_DB].dbo.VaultEntries ve ON ve.Id = ef.EntryId
WHERE ve.Id IS NULL;
"
ORPHANS=$($SQLCMD_CMD $SQLCMD_ARGS -Q "$FK_SQL" -h-1 -W 2>/dev/null | grep -E '^[0-9]+$' | head -1)
if [ "$ORPHANS" = "0" ]; then
    echo "  FK VaultEntries -> EntryFields: OK (0 orphans)"
elif [ -n "$ORPHANS" ]; then
    echo "  WARNING: $ORPHANS orphan EntryField rows (EntryId with no parent)"
    FAILURES=$((FAILURES + 1))
else
    echo "  WARNING: Could not verify FK VaultEntries -> EntryFields"
    FAILURES=$((FAILURES + 1))
fi

# ---- Step 6: Summary ----
echo ""
echo "[6/7] Drill results:"
if [ "$FAILURES" -eq 0 ]; then
    echo "  ALL CHECKS PASSED — backup is valid and restorable."
else
    echo "  $FAILURES check(s) FAILED."
fi

# ---- Step 7: Clean up (drop test database) ----
echo "[7/7] Cleaning up — dropping [$TEST_DB]..."
$SQLCMD_CMD $SQLCMD_ARGS -Q "
IF DB_ID('$TEST_DB') IS NOT NULL
BEGIN
    ALTER DATABASE [$TEST_DB] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE [$TEST_DB];
    PRINT 'Dropped [$TEST_DB]';
END
" 2>&1 || echo "  (Could not drop test database — manual cleanup may be needed)"

echo ""
echo "=== Restore drill finished: $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
exit $FAILURES
