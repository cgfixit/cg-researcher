#!/bin/bash
# One-shot scan of recent corpus files. macOS /bin/bash 3.2 (no arrays, no ${var,,}).
# State is files under $CG_HOME. This script does not loop, wait for a network, or
# extract .docx text. The product index does extraction. See collect_files in
# crates/cg-core/src/rag.rs.
set -euo pipefail
umask 077

CG_HOME="${CG_HOME:-${HOME:-}/.cg-researcher}"
CG_CORPUS_DIR="${CG_CORPUS_DIR:-}"
CG_SCAN_DOWNLOADS="${CG_SCAN_DOWNLOADS:-0}"
CG_CORPUS_SCAN_TO="${CG_CORPUS_SCAN_TO:-}"
MODE="scan"
SCAN_HOUR_AM=4
SCAN_HOUR_PM=16
MAIL_HOUR_AM=9
MAIL_HOUR_PM=18
MAIL_MINUTE_PM=30
LABEL_SCAN="com.cgfixit.cg-researcher.corpus-scan"
LABEL_MAIL="com.cgfixit.cg-researcher.corpus-mail"
PATH="/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin"
# macOS ships shasum in /usr/bin. Git for Windows puts the same perl script under core_perl.
if [[ ! -x /usr/bin/shasum && -x /usr/bin/core_perl/shasum ]]; then
  PATH="$PATH:/usr/bin/core_perl"
fi
export PATH

SCRIPT_PATH=""
CORPUS=""
LOG_DIR=""
STATE_DIR=""
STATE_FILE=""
DREAM_FILE=""
LOCKDIR=""
LOCK_OWNED=0
LIST_FILE=""
REPORT_TMP=""
STATE_TMP=""

usage() {
  cat <<'EOF'
daily-corpus-scan.sh — one-shot corpus scan for cg-researcher

  --home PATH     data directory (default $CG_HOME or ~/.cg-researcher)
  --corpus PATH   corpus directory (default <home>/corpus). Does not read cg.toml.
  --downloads     also hash recent .md .markdown .txt .docx files in ~/Downloads
  --mail          send the latest report; do not scan
  --print-scan-plist
  --print-mail-plist
  --print-cron
  --help

Scan times in the plist and cron are 04:00 and 16:00 local. Mail times are
09:00 and 18:30 local. Set the Mac time zone for Eastern wall time. A missed
launchd calendar fire runs once on wake. The file window stays find -mtime -1.
cron does not catch up. --mail needs CG_CORPUS_SCAN_TO in that job's environment.
EOF
}

die() {
  printf '%s\n' "$1" >&2
  exit "${2:-1}"
}

cleanup() {
  if [[ -n "${WORKDIR:-}" && -d "$WORKDIR" ]]; then
    rm -rf -- "$WORKDIR"
  fi
  if [[ "$LOCK_OWNED" == 1 && -n "$LOCKDIR" && -d "$LOCKDIR" ]]; then
    rm -f "$LOCKDIR/pid"
    rmdir "$LOCKDIR" 2>/dev/null || true
  fi
}

ensure_work() {
  if [[ -z "${WORKDIR:-}" ]]; then
    WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/cg-corpus-scan.XXXXXX")
  fi
}

xml_escape() {
  local s="$1"
  s=${s//&/&amp;}
  s=${s//</&lt;}
  s=${s//>/&gt;}
  printf '%s' "$s"
}

script_path() {
  local dir base
  dir=$(CDPATH='' cd -P "$(dirname "$0")" && pwd) || die "cannot resolve script directory"
  base=$(basename -- "$0")
  printf '%s/%s' "$dir" "$base"
}

require_absolute() {
  local what="$1" path="$2"
  case "$path" in
    /*) ;;
    *) die "$what must be an absolute path: $path" ;;
  esac
  case "$path" in
    *$'\n'*|*'#'*|*'&'*|*'\'*|*"'"*|*'%'*) die "$what contains a character this script will not schedule: $path" ;;
  esac
}

acquire_lock() {
  local old=""
  LOCKDIR="$STATE_DIR/corpus-scan.lock"
  if mkdir "$LOCKDIR" 2>/dev/null; then
    printf '%s\n' "$$" > "$LOCKDIR/pid"
    LOCK_OWNED=1
    return 0
  fi
  # Wait out the mkdir-then-pid write. After that, an empty pid is a crash.
  if [[ ! -s "$LOCKDIR/pid" ]]; then
    sleep 1
  fi
  if [[ -s "$LOCKDIR/pid" ]]; then
    old=$(cat "$LOCKDIR/pid" 2>/dev/null || true)
  fi
  if [[ -n "$old" ]] && scan_still_running "$old"; then
    LOCKDIR=""
    die "another corpus scan is running (pid $old)" 75
  fi
  # Move a dead lock aside. If the move fails, another process took it.
  stale="$STATE_DIR/corpus-scan.lock.stale.$$"
  if ! mv -- "$LOCKDIR" "$stale" 2>/dev/null; then
    LOCKDIR=""
    die "another corpus scan is running" 75
  fi
  if ! mkdir "$LOCKDIR" 2>/dev/null; then
    rm -rf -- "$stale"
    LOCKDIR=""
    die "another corpus scan is running" 75
  fi
  printf '%s\n' "$$" > "$LOCKDIR/pid"
  LOCK_OWNED=1
  rm -rf -- "$stale"
}

scan_still_running() {
  local pid="$1" cmd=""
  kill -0 "$pid" 2>/dev/null || return 1
  cmd=$(ps -p "$pid" -o args= 2>/dev/null || true)
  if [[ -z "$cmd" ]]; then
    cmd=$(ps -p "$pid" -o command= 2>/dev/null || true)
  fi
  # ps failed: do not steal a pid we cannot name.
  [[ -n "$cmd" ]] || return 0
  case "$cmd" in
    *daily-corpus-scan.sh*) return 0 ;;
    *) return 1 ;;
  esac
}

ext_of() {
  local base ext
  base=$(basename -- "$1")
  case "$base" in
    *.*) ext=$(printf '%s' "${base##*.}" | tr '[:upper:]' '[:lower:]') ;;
    *) ext="" ;;
  esac
  printf '%s' "$ext"
}

allowed_ext() {
  case "$1" in
    md|markdown|txt|docx) return 0 ;;
    *) return 1 ;;
  esac
}

# The indexer rejects a NUL anywhere in a text file. .docx is a zip and is hashed whole.
is_nul_text() {
  local rc=0
  # Command substitution drops NUL bytes, so grep on a substituted NUL never sees one.
  # od prints a decimal 0 for every NUL in the whole file. The indexer rejects any NUL.
  od -An -t u1 -v "$1" | grep -Eq '(^|[[:space:]])0([[:space:]]|$)' || rc=$?
  if [[ "$rc" -eq 0 ]]; then
    return 0
  fi
  if [[ "$rc" -eq 1 ]]; then
    return 1
  fi
  return 2
}

file_hash() {
  local line hash
  line=$(shasum -a 256 -b -- "$1") || return 1
  hash=${line%% *}
  [[ ${#hash} -eq 64 ]] || return 1
  case "$hash" in
    *[!0-9a-f]*) return 1 ;;
  esac
  printf '%s' "$hash"
}

file_bytes() {
  local n
  n=$(wc -c < "$1") || return 1
  printf '%s' "$n" | tr -d '[:space:]'
}

lookup_hash() {
  local want="$1" hash bytes path
  [[ -f "$STATE_FILE" ]] || return 0
  while IFS="$(printf '\t')" read -r hash bytes path || [[ -n "${hash:-}" ]]; do
    case "$hash" in
      ''|'#'*) continue ;;
    esac
    if [[ "$path" == "$want" ]]; then
      printf '%s' "$hash"
      return 0
    fi
  done < "$STATE_FILE"
}

path_was_scanned() {
  local file="$1" want="$2" hash bytes path
  [[ -f "$file" ]] || return 1
  while IFS="$(printf '\t')" read -r hash bytes path || [[ -n "${hash:-}" ]]; do
    if [[ "$path" == "$want" ]]; then
      return 0
    fi
  done < "$file"
  return 1
}

last_dream_when() {
  local last rest
  [[ -f "$DREAM_FILE" ]] || return 0
  last=$(tail -n 1 "$DREAM_FILE" 2>/dev/null || true)
  case "$last" in
    when=*)
      rest=${last#when=}
      printf '%s' "${rest%%$'\t'*}"
      ;;
  esac
}

find_cg() {
  if [[ -x "$CG_HOME/bin/cg-researcher" ]]; then
    printf '%s' "$CG_HOME/bin/cg-researcher"
    return 0
  fi
  if command -v cg-researcher >/dev/null 2>&1; then
    command -v cg-researcher
    return 0
  fi
  return 1
}

valid_recipient() {
  local to="$1"
  case "$to" in
    ''|-*|*' '*|*$'\t'*|*$'\n'*|*'@'*'@'*|*'%'*) return 1 ;;
  esac
  case "$to" in
    *[!A-Za-z0-9._%+-@]*) return 1 ;;
  esac
  case "$to" in
    *@*.*) return 0 ;;
    *) return 1 ;;
  esac
}

latest_report() {
  local found
  # C locale so "-" and "." sort by byte, not by the operator's dictionary order.
  found=$(find "$LOG_DIR" -maxdepth 1 -type f -name 'corpus-scan-*.md' | LC_ALL=C sort | tail -n 1)
  printf '%s' "$found"
}

send_report() {
  local to="$1" report="$2" msmtp="" candidate
  valid_recipient "$to" || die "CG_CORPUS_SCAN_TO must be one plain address. Mail was not sent." 2
  [[ -f "$report" ]] || die "no corpus scan report to send" 1
  for candidate in /opt/homebrew/bin/msmtp /usr/local/bin/msmtp; do
    if [[ -x "$candidate" ]]; then
      msmtp=$candidate
      break
    fi
  done
  # One attempt. The next calendar slot is the retry. No password is passed on argv.
  # msmtp reads its account from the operator's own config. /usr/bin/mail submits locally.
  if [[ -n "$msmtp" ]]; then
    {
      printf 'To: %s\n' "$to"
      printf 'Subject: cg-researcher corpus scan\n'
      printf 'MIME-Version: 1.0\n'
      printf 'Content-Type: text/plain; charset=UTF-8\n'
      printf '\n'
      cat -- "$report"
    } | "$msmtp" -t
    return $?
  fi
  if [[ -x /usr/bin/mail ]]; then
    /usr/bin/mail -s "cg-researcher corpus scan" "$to" < "$report"
    return $?
  fi
  die "neither msmtp nor /usr/bin/mail is installed. Mail was not sent." 1
}

plist_header() {
  local label="$1"
  cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$label</string>
EOF
}

plist_footer() {
  local home_xml="$1" log_name="$2" extra_env="${3:-}"
  cat <<EOF
  <key>RunAtLoad</key><false/>
  <key>ProcessType</key><string>Background</string>
  <key>LowPriorityIO</key><true/>
  <key>Nice</key><integer>10</integer>
  <key>LimitLoadToSessionType</key><string>Aqua</string>
  <key>Umask</key><integer>63</integer>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin</string>
$extra_env
  </dict>
  <key>StandardOutPath</key><string>$home_xml/logs/$log_name</string>
  <key>StandardErrorPath</key><string>$home_xml/logs/$log_name</string>
</dict>
</plist>
EOF
}

print_scan_plist() {
  local bin_xml home_xml
  bin_xml=$(xml_escape "$SCRIPT_PATH")
  home_xml=$(xml_escape "$CG_HOME")
  plist_header "$LABEL_SCAN"
  cat <<EOF
  <key>ProgramArguments</key>
  <array>
    <string>$bin_xml</string>
    <string>--home</string>
    <string>$home_xml</string>
  </array>
  <key>StartCalendarInterval</key>
  <array>
    <dict><key>Hour</key><integer>$SCAN_HOUR_AM</integer><key>Minute</key><integer>0</integer></dict>
    <dict><key>Hour</key><integer>$SCAN_HOUR_PM</integer><key>Minute</key><integer>0</integer></dict>
  </array>
EOF
  plist_footer "$home_xml" "corpus-scan.launchd.log"
}

print_mail_plist() {
  local bin_xml home_xml extra="" to_xml
  bin_xml=$(xml_escape "$SCRIPT_PATH")
  home_xml=$(xml_escape "$CG_HOME")
  if valid_recipient "$CG_CORPUS_SCAN_TO"; then
    to_xml=$(xml_escape "$CG_CORPUS_SCAN_TO")
    extra="    <key>CG_CORPUS_SCAN_TO</key><string>$to_xml</string>"
  fi
  plist_header "$LABEL_MAIL"
  cat <<EOF
  <!-- When CG_CORPUS_SCAN_TO is set at print time, it is copied below.
       Otherwise add that key before bootstrap. Mail exits 2 until it is set. -->
  <key>ProgramArguments</key>
  <array>
    <string>$bin_xml</string>
    <string>--home</string>
    <string>$home_xml</string>
    <string>--mail</string>
  </array>
  <key>StartCalendarInterval</key>
  <array>
    <dict><key>Hour</key><integer>$MAIL_HOUR_AM</integer><key>Minute</key><integer>0</integer></dict>
    <dict><key>Hour</key><integer>$MAIL_HOUR_PM</integer><key>Minute</key><integer>$MAIL_MINUTE_PM</integer></dict>
  </array>
EOF
  plist_footer "$home_xml" "corpus-mail.launchd.log" "$extra"
}

print_cron() {
  local mail_prefix=""
  if valid_recipient "$CG_CORPUS_SCAN_TO"; then
    mail_prefix="CG_CORPUS_SCAN_TO='$CG_CORPUS_SCAN_TO' "
  fi
  cat <<EOF
# cg-researcher corpus scan. Times are this Mac's local clock.
# Install this file OR the launchd plists, not both.
# cron does not run a job missed during sleep. launchd StartCalendarInterval does,
# and coalesces several missed fires into one run on wake.
# That run still uses find -mtime -1. It does not look further back.
# Do not put an SMTP password in this file.
0 $SCAN_HOUR_AM * * * '$SCRIPT_PATH' --home '$CG_HOME'
0 $SCAN_HOUR_PM * * * '$SCRIPT_PATH' --home '$CG_HOME'
0 $MAIL_HOUR_AM * * * ${mail_prefix}'$SCRIPT_PATH' --home '$CG_HOME' --mail
$MAIL_MINUTE_PM $MAIL_HOUR_PM * * * ${mail_prefix}'$SCRIPT_PATH' --home '$CG_HOME' --mail
EOF
}

prepare_paths() {
  require_absolute "home" "$CG_HOME"
  case "$CG_HOME" in
    /) die "refusing home /" ;;
  esac
  if [[ -n "$CG_CORPUS_DIR" ]]; then
    CORPUS=$CG_CORPUS_DIR
  else
    CORPUS="$CG_HOME/corpus"
  fi
  require_absolute "corpus" "$CORPUS"
  LOG_DIR="$CG_HOME/logs"
  STATE_DIR="$CG_HOME/state"
  STATE_FILE="$STATE_DIR/corpus-scan.tsv"
  DREAM_FILE="$LOG_DIR/dream.log"
}

collect_into() {
  local root="$1" out="$2" f ext rc
  [[ -d "$root" ]] || return 1
  ensure_work
  LIST_FILE="$WORKDIR/list"
  # collect_files starts at depth 0 and still reads a directory at depth 8.
  # That directory's files are nine find levels below the corpus root.
  # -H follows a symlinked start directory, matching collect_files on the corpus root.
  # Inner symlinks stay unfollowed. A find error is recorded and the scan still finishes.
  find -H "$root" -maxdepth 9 -type f -mtime -1 -print0 > "$LIST_FILE" || printf 'find-failed\t%s\n' "$root" >> "$out.skip"
  while IFS= read -r -d '' f || [[ -n "${f:-}" ]]; do
    [[ -n "$f" ]] || continue
    case "$f" in
      *$'\t'*|*$'\n'*|*\`*)
        printf 'path-rejected\t%s\n' "$f" >> "$out.skip"
        continue
        ;;
    esac
    if [[ -f "$out" ]] && grep -F -x -q -e "$f" "$out"; then
      continue
    fi
    ext=$(ext_of "$f")
    if ! allowed_ext "$ext"; then
      continue
    fi
    if [[ "$ext" != "docx" ]]; then
      rc=0
      is_nul_text "$f" || rc=$?
      if [[ "$rc" -eq 0 ]]; then
        printf 'binary\t%s\n' "$f" >> "$out.skip"
        continue
      fi
      if [[ "$rc" -eq 2 ]]; then
        printf 'unreadable\t%s\n' "$f" >> "$out.skip"
        continue
      fi
    fi
    if [[ ! -r "$f" ]]; then
      printf 'unreadable\t%s\n' "$f" >> "$out.skip"
      continue
    fi
    printf '%s\n' "$f" >> "$out"
  done < "$LIST_FILE"
  rm -f "$LIST_FILE"
  LIST_FILE=""
}

append_dream() {
  local previous="$1" sources="$2" changed="$3" elapsed="$4"
  # previous= is for a person reading this log. It does not widen find -mtime -1.
  # No CPU threshold: this product does not define "spare resources".
  printf 'when=%s\tran=yes\tprevious=%s\telapsed_s=%s\tsources=%s\tchanged=%s\n' \
    "$(date '+%Y-%m-%dT%H:%M:%S%z')" \
    "${previous:-never}" \
    "$elapsed" \
    "$sources" \
    "$changed" >> "$DREAM_FILE"
  chmod 600 "$DREAM_FILE"
}

run_scan() {
  local previous bin scanned skipfile hash bytes old status
  local sources=0 changed=0 unchanged=0
  local stamp report dest n=0 ask_note
  local f parent
  prepare_paths
  ensure_work
  [[ -d "$CORPUS" ]] || die "corpus directory does not exist: $CORPUS"
  command -v find >/dev/null 2>&1 || die "find is required"
  command -v shasum >/dev/null 2>&1 || die "shasum is required"
  command -v od >/dev/null 2>&1 || die "od is required"
  mkdir -p "$STATE_DIR" "$LOG_DIR"
  chmod 700 "$STATE_DIR" "$LOG_DIR" || die "cannot restrict permissions on $STATE_DIR or $LOG_DIR"
  acquire_lock
  previous=$(last_dream_when || true)
  [[ -n "$previous" ]] || previous="never"
  scanned="$WORKDIR/scanned"
  skipfile="$WORKDIR/scanned.skip"
  : > "$scanned"
  : > "$skipfile"
  collect_into "$CORPUS" "$scanned" || die "cannot read corpus: $CORPUS"
  if [[ "$CG_SCAN_DOWNLOADS" == "1" ]]; then
    if [[ -d "${HOME:-}/Downloads" ]]; then
      require_absolute "Downloads" "${HOME}/Downloads"
      collect_into "${HOME}/Downloads" "$scanned" || printf 'unreadable\t%s\n' "${HOME}/Downloads" >> "$skipfile"
    else
      printf 'missing\t%s\n' "${HOME:-}/Downloads" >> "$skipfile"
    fi
  fi
  # Same directory as the destination so mv is a rename, not a cross-device copy.
  STATE_TMP="$STATE_DIR/.corpus-scan-tsv.$$"
  REPORT_TMP="$LOG_DIR/.corpus-scan-report.$$"
  : > "$STATE_TMP"
  {
    printf '# Corpus scan\n\n'
    printf -- '- When: %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z %Z')"
    printf -- '- Home: %s\n' "$CG_HOME"
    printf -- '- Corpus: %s\n' "$CORPUS"
    printf -- '- Window: find -mtime -1 (less than 1 day). Not a 12 hour window.\n'
    if [[ "$CG_SCAN_DOWNLOADS" == "1" ]]; then
      printf -- '- Downloads: %s\n' "${HOME:-}/Downloads"
    else
      printf -- '- Downloads: off\n'
    fi
    printf '\n## Sources\n\n'
  } > "$REPORT_TMP"
  : > "$REPORT_TMP.changed"
  : > "$REPORT_TMP.same"
  while IFS= read -r f || [[ -n "${f:-}" ]]; do
    [[ -n "$f" ]] || continue
    hash=$(file_hash "$f") || {
      printf 'hash-failed\t%s\n' "$f" >> "$skipfile"
      continue
    }
    bytes=$(file_bytes "$f") || bytes="?"
    old=$(lookup_hash "$f" || true)
    if [[ -z "$old" ]]; then
      status="new"
      changed=$((changed + 1))
    elif [[ "$old" == "$hash" ]]; then
      status="unchanged"
      unchanged=$((unchanged + 1))
    else
      status="changed"
      changed=$((changed + 1))
    fi
    sources=$((sources + 1))
    printf '%s\t%s\t%s\n' "$hash" "$bytes" "$f" >> "$STATE_TMP"
    printf -- '- `%s` (%s bytes, sha256 `%s`, %s)\n' "$f" "$bytes" "$hash" "$status" >> "$REPORT_TMP"
    if [[ "$status" == "unchanged" ]]; then
      printf -- '- `%s`\n' "$f" >> "$REPORT_TMP.same"
    else
      printf -- '- `%s` (%s)\n' "$f" "$status" >> "$REPORT_TMP.changed"
    fi
  done < "$scanned"
  if [[ "$sources" -eq 0 ]]; then
    printf 'none\n' >> "$REPORT_TMP"
  fi
  printf '\n## Changed since last scan\n\n' >> "$REPORT_TMP"
  if [[ -s "$REPORT_TMP.changed" ]]; then
    cat "$REPORT_TMP.changed" >> "$REPORT_TMP"
  else
    printf 'none\n' >> "$REPORT_TMP"
  fi
  printf '\n## Unchanged in this window\n\n' >> "$REPORT_TMP"
  if [[ -s "$REPORT_TMP.same" ]]; then
    cat "$REPORT_TMP.same" >> "$REPORT_TMP"
  else
    printf 'none\n' >> "$REPORT_TMP"
  fi
  rm -f "$REPORT_TMP.changed" "$REPORT_TMP.same"
  {
    printf '\n## Skipped\n\n'
  } >> "$REPORT_TMP"
  if [[ -s "$skipfile" ]]; then
    while IFS="$(printf '\t')" read -r status f || [[ -n "${status:-}" ]]; do
      [[ -n "$status" ]] || continue
      printf -- '- %s: %s\n' "$status" "$f" >> "$REPORT_TMP"
    done < "$skipfile"
  else
    printf 'none\n' >> "$REPORT_TMP"
  fi
  bin=$(find_cg || true)
  ask_note="Not extracted by this script. Byte hashes detect changes. Text extraction stays in the product index."
  {
    printf '\n## Connections\n\n%s\n' "$ask_note"
    printf '\n## Patterns\n\n%s\n' "$ask_note"
    printf '\n## Insights\n\n%s\n' "$ask_note"
    printf '\n## Incomplete conclusions\n\n%s\n' "$ask_note"
    printf '\n## Open research questions\n\n%s\n' "$ask_note"
  } >> "$REPORT_TMP"
  {
    printf '\n## Index\n\n'
    printf "    cg-researcher --home '%s' index\n" "$CG_HOME"
    if [[ -n "$bin" ]]; then
      printf "    '%s' --home '%s' index\n" "$bin" "$CG_HOME"
    fi
    printf '\n## Ask the local model\n\n'
    printf "    cg-researcher --home '%s' chat\n" "$CG_HOME"
    if [[ -n "$bin" ]]; then
      printf "    '%s' --home '%s' chat\n" "$bin" "$CG_HOME"
    fi
    printf '\nQuestion to paste: Review the indexed notes. List connections, patterns, insights, incomplete conclusions, and specific open research questions. Cite source paths.\n'
    printf '\n## Email\n\nnot sent. This scan does not send mail. The mail job passes --mail.\n'
  } >> "$REPORT_TMP"
  # Keep hash rows for files outside this window so the next change is visible.
  if [[ -f "$STATE_FILE" ]]; then
    while IFS="$(printf '\t')" read -r hash bytes f || [[ -n "${hash:-}" ]]; do
      case "$hash" in
        ''|'#'*) continue ;;
      esac
      # Drop a file only when its parent directory is still there. A missing
      # parent may be an unmounted volume, and the hash baseline should survive that.
      parent=$(dirname -- "$f")
      if [[ -d "$parent" && ! -e "$f" ]]; then
        printf -- '- removed: %s\n' "$f" >> "$REPORT_TMP.removed"
        continue
      fi
      if path_was_scanned "$STATE_TMP" "$f"; then
        continue
      fi
      printf '%s\t%s\t%s\n' "$hash" "$bytes" "$f" >> "$STATE_TMP.keep"
    done < "$STATE_FILE"
  fi
  if [[ -s "$REPORT_TMP.removed" ]]; then
    printf '\n## Removed\n\n' >> "$REPORT_TMP"
    cat "$REPORT_TMP.removed" >> "$REPORT_TMP"
  fi
  stamp=$(date '+%Y%m%dT%H%M%S')
  # Always suffix -NN so a later file in the same second sorts after the earlier one.
  while true; do
    dest=$(printf '%s/corpus-scan-%s-%02d.md' "$LOG_DIR" "$stamp" "$n")
    [[ -e "$dest" ]] || break
    n=$((n + 1))
    [[ "$n" -lt 100 ]] || die "too many reports in the same second"
  done
  chmod 600 "$REPORT_TMP"
  rm -f "$REPORT_TMP.removed"
  mv -f "$REPORT_TMP" "$dest"
  REPORT_TMP=""
  {
    printf '# cg-researcher corpus-scan hashes v1\n'
    if [[ -f "$STATE_TMP.keep" ]]; then
      cat "$STATE_TMP.keep"
    fi
    cat "$STATE_TMP"
  } > "$STATE_TMP.out"
  chmod 600 "$STATE_TMP.out"
  mv -f "$STATE_TMP.out" "$STATE_FILE"
  rm -f "$STATE_TMP" "$STATE_TMP.keep"
  STATE_TMP=""
  append_dream "$previous" "$sources" "$changed" "$SECONDS"
  rm -f "$scanned" "$skipfile"
  printf '%s\n' "$dest"
}

run_mail() {
  local report
  prepare_paths
  # Mail only reads a finished report. It does not take the scan lock, so a
  # coalesced wake can send while a scan is still hashing.
  [[ -d "$LOG_DIR" ]] || die "no corpus-scan report under $LOG_DIR" 1
  report=$(latest_report || true)
  [[ -n "$report" ]] || die "no corpus-scan report under $LOG_DIR" 1
  send_report "$CG_CORPUS_SCAN_TO" "$report"
  printf 'sent %s\n' "$report"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --home)
      [[ $# -ge 2 ]] || die "missing value for --home" 2
      CG_HOME=$2
      shift 2
      ;;
    --corpus)
      [[ $# -ge 2 ]] || die "missing value for --corpus" 2
      CG_CORPUS_DIR=$2
      shift 2
      ;;
    --downloads) CG_SCAN_DOWNLOADS=1; shift ;;
    --mail) MODE="mail"; shift ;;
    --print-scan-plist) MODE="print-scan"; shift ;;
    --print-mail-plist) MODE="print-mail"; shift ;;
    --print-cron) MODE="print-cron"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" 2 ;;
  esac
done

trap cleanup EXIT
SCRIPT_PATH=$(script_path)
require_absolute "script" "$SCRIPT_PATH"
require_absolute "home" "$CG_HOME"

case "$MODE" in
  print-scan) print_scan_plist; exit 0 ;;
  print-mail) print_mail_plist; exit 0 ;;
  print-cron) print_cron; exit 0 ;;
  mail) run_mail; exit 0 ;;
  scan) run_scan; exit 0 ;;
  *) die "unknown mode" 2 ;;
esac
