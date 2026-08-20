#!/bin/sh
# Install the nmap-vulners scripts where the local nmap will find them.
#
# From a checkout:            ./install.sh
# Without one:                curl -fsSL https://raw.githubusercontent.com/
#                               vulnersCom/nmap-vulners/master/install.sh | sh
# Without root:               ./install.sh --user
# Somewhere specific:         ./install.sh --prefix /usr/local/share/nmap
# Removing it again:          ./install.sh --uninstall
#
# Other options:
#   --ref REF     install this branch or tag instead of master (download mode)
#   --no-key      do not offer to store an API key
#   --help
#
# macOS, Linux, Kali, WSL - anything with a POSIX shell. Windows uses
# install.ps1.

set -eu

REPO_RAW="https://raw.githubusercontent.com/vulnersCom/nmap-vulners"
REF="master"
PREFIX=""
MODE="system"
ACTION="install"
ASK_KEY="yes"

# 2.0 is one file that downloads its dictionaries at scan time. The 1.x trio
# is still listed, because
# installing over it has to REMOVE it: a leftover http-vulners-regex.nse
# carries
# the "default" category and keeps sweeping targets under a plain -sC, which is
# exactly what this release stopped doing.
SCRIPTS="vulners.nse"
DATA=""
LEGACY_SCRIPTS="http-vulners-regex.nse vulners_enterprise.nse"
LEGACY_DATA="http-vulners-regex.json http-vulners-paths.txt"

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
# Printed from the comment block at the top, so the two cannot drift apart.
# Bounded by the end of that block rather than a line number, which is what
# broke the moment an option was added.
usage() { sed -n '2,/^[^#]/p' "$0" | sed -n 's/^# \{0,1\}//p'; exit 0; }

while [ $# -gt 0 ]; do
  case "$1" in
    --user) MODE="user"; shift ;;
    --prefix)
      PREFIX="${2:-}"
      [ -n "$PREFIX" ] || die "--prefix needs a directory"
      MODE="prefix"; shift 2 ;;
    --ref)
      REF="${2:-}"
      [ -n "$REF" ] || die "--ref needs a branch or tag"; shift 2 ;;
    --uninstall) ACTION="uninstall"; shift ;;
    --no-key) ASK_KEY="no"; shift ;;
    -h|--help) usage ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
done

command -v nmap >/dev/null 2>&1 || die "nmap is not installed, or not in PATH"

# Ask nmap where it reads its data from. Under -d2 it names every file it
# opens, and --script-help sends no packets, so the directory holding
# nse_main.lua is the one this nmap actually uses - whatever the build,
# the package manager or NMAPDIR decided.
system_datadir() {
  # The probe name is meant not to exist: nmap prints what it opened and then
  # exits non-zero, which must not take the installer with it.
  reported=$(nmap -d2 --script-help nmap-vulners-install-probe 2>&1 |
             sed -n 's|^Fetchfile found \(.*\)/nse_main\.lua$|\1|p' |
             head -n 1 || true)

  if [ -n "$reported" ] && [ -d "$reported" ]; then
    # It can arrive as /usr/bin/../share/nmap; resolve for readability.
    (cd "$reported" && pwd)
    return
  fi

  for candidate in /usr/share/nmap /usr/local/share/nmap \
                   /opt/homebrew/share/nmap /opt/local/share/nmap; do
    [ -d "$candidate/nselib" ] && { printf '%s\n' "$candidate"; return; }
  done

  die "cannot find nmap's data directory; pass --prefix /path/to/share/nmap"
}

case "$MODE" in
  user)   DATADIR="${NMAPDIR:-$HOME/.nmap}" ;;
  prefix) DATADIR="$PREFIX" ;;
  *)      DATADIR=$(system_datadir) ;;
esac

SCRIPTDIR="$DATADIR/scripts"
DATASUBDIR="$DATADIR/nselib/data"

# Can this user write there? A path that does not exist yet is writable if the
# nearest directory that does exist is.
writable() {
  path="$1"
  while [ ! -e "$path" ] && [ "$path" != "/" ] && [ "$path" != "." ]; do
    path=$(dirname "$path")
  done
  [ -w "$path" ]
}

# sudo only where the target is genuinely not writable, and never in --user
# mode, where needing root would mean something is wrong rather than expected.
run_at() {
  target="$1"; shift
  if [ "$(id -u)" = "0" ] || writable "$target"; then
    "$@"
  elif [ "$MODE" = "user" ]; then
    die "$target is not writable"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    die "$target is not writable and there is no sudo; re-run as root, or
 use --user"
  fi
}

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$2" "$1"
  else
    die "need curl or wget to download $1"
  fi
}

update_db() {
  if [ "$MODE" = "system" ]; then
    run_at "$SCRIPTDIR" nmap --script-updatedb >/dev/null
  else
    NMAPDIR="$DATADIR" nmap --script-updatedb >/dev/null
  fi
}

# --------------------------------------------------------------- API key
#
# The script itself never asks for a key: it runs inside nmap, where there is
# no terminal to prompt on and where writing a file would be a surprise. The
# installer is the one moment a person is present, so it is the one place that
# can ask.

# Where nmap looks for it. nmap resolves ~/.nmap through getpwuid(getuid()),
# not $HOME, so under sudo the file has to go to the invoking user's home and
# be owned by them - otherwise the key is written somewhere nmap will never
# read, owned by somebody who cannot edit it.
key_home() {
  if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
    eval "printf '%s' ~${SUDO_USER}"
  else
    printf '%s' "$HOME"
  fi
}

# Ask the API whether a token is good. This endpoint costs no credits and
# needs no arguments, which makes it the cheapest possible question.
validate_key() {
  key=$1
  if command -v curl >/dev/null 2>&1; then
    code=$(curl -sS -o /dev/null -w '%{http_code}' \
      -H "X-Api-Key: $key" \
      -H "User-Agent: Vulners NMAP Plugin installer" \
      "https://vulners.com/api/v3/audit/getSupportedOS/" 2>/dev/null \
      || printf '000')
  elif command -v wget >/dev/null 2>&1; then
    code=$(wget -qS -O /dev/null \
      --header="X-Api-Key: $key" \
      --header="User-Agent: Vulners NMAP Plugin installer" \
      "https://vulners.com/api/v3/audit/getSupportedOS/" 2>&1 |
      sed -n 's/.*HTTP\/[0-9.]* \([0-9]*\).*/\1/p' | tail -n 1)
    [ -n "$code" ] || code="000"
  else
    printf 'skip'
    return 0
  fi

  case "$code" in
    200) printf 'ok' ;;
    401|403) printf 'bad' ;;
    402) printf 'unlicensed' ;;
    429) printf 'ratelimited' ;;
    000) printf 'unreachable' ;;
    *) printf 'unknown:%s' "$code" ;;
  esac
}

# Write it where nmap will find it, readable only by its owner.
#
# Written to a temporary file and renamed, so an interrupted install cannot
# leave a half-written token behind that then fails every scan with a 401 and
# nothing to say why.
store_key() {
  key=$1
  home=$(key_home)
  dir="$home/.nmap"
  file="$dir/vulners.key"

  mkdir -p "$dir" || { say "  could not create $dir"; return 1; }
  umask 077
  printf '%s\n' "$key" > "$file.tmp" \
    || { say "  could not write $file"; return 1; }
  chmod 600 "$file.tmp"
  mv -f "$file.tmp" "$file"

  if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
    chown "$SUDO_USER" "$file" 2>/dev/null || true
    chown "$SUDO_USER" "$dir" 2>/dev/null || true
  fi

  say "  saved to $file (readable only by its owner)"
  return 0
}

offer_key_entry() {
  [ "$ASK_KEY" = "no" ] && return 0

  # Nothing to ask if one is already configured.
  if [ -n "${VULNERS_API_KEY:-}" ]; then
    say ""
    say "VULNERS_API_KEY is already set in the environment; leaving it alone."
    return 0
  fi
  existing="$(key_home)/.nmap/vulners.key"
  if [ -f "$existing" ]; then
    say ""
    say "A key is already stored in $existing; leaving it alone."
    return 0
  fi

  # The question is asked on the terminal, not on stdin, and it has to be:
  # installed the documented way - curl ... | sh - stdin is the pipe carrying
  # this script, so testing it found no terminal and skipped the offer on
  # exactly the path most people take. Reading it would be worse than useless,
  # because sh has not finished parsing what is still coming down it.
  #
  # No controlling terminal - CI, a Dockerfile, cron - and there is nobody to
  # answer, so say where a key goes and carry on.
  if ! { exec 3<>/dev/tty; } 2>/dev/null; then
    say ""
    say "No API key configured. It works without one; to add one later,"
    say "in $existing or set VULNERS_API_KEY."
    return 0
  fi

  say ""
  say "An API key is optional. Without one the scan uses the free lookup."
  say "A free key adds detail per finding and can identify software the free"
  say "lookup cannot name. Get one at https://vulners.com/userinfo"
  say ""
  say "Anything you enter is sent to vulners.com once, to check it works,"
  say "and then stored in $existing."
  printf 'Paste a key, or press Enter to skip: '

  # Read without echoing: a key pasted into a terminal otherwise stays in the
  # scrollback and in any recording of the session.
  if stty -echo <&3 2>/dev/null; then
    read -r entered <&3 || entered=""
    stty echo <&3 2>/dev/null
    printf '\n'
  else
    read -r entered <&3 || entered=""
  fi
  exec 3>&-

  entered=$(printf '%s' "$entered" | tr -d '[:space:]')
  if [ -z "$entered" ]; then
    say "No key entered; the scan will use the free lookup."
    return 0
  fi

  say "Checking it with vulners.com..."
  case "$(validate_key "$entered")" in
    ok)
      say "  the key works."
      store_key "$entered" || true
      ;;
    bad)
      say "  vulners.com does not recognise that key; it was NOT saved."
      say "  Check it at https://vulners.com/userinfo, then put the key in"
      say "  $existing yourself, or re-run this installer."
      ;;
    unlicensed)
      say "  that key is recognised but has no licence; it was NOT saved."
      ;;
    ratelimited)
      say "  vulners.com is rate limiting right now, so the key could not be"
      say "  checked. Saving it anyway - it is probably fine."
      store_key "$entered" || true
      ;;
    unreachable|skip)
      say "  could not reach vulners.com to check it. Saving it unchecked."
      store_key "$entered" || true
      ;;
    unknown:*)
      say "  unexpected answer from vulners.com; the key was NOT saved."
      ;;
  esac
}

remove_legacy() {
  removed=""
  for name in $LEGACY_SCRIPTS; do
    if [ -f "$SCRIPTDIR/$name" ]; then
      run_at "$SCRIPTDIR" rm -f "$SCRIPTDIR/$name"
      removed="$removed  scripts/$name
"
    fi
  done
  for name in $LEGACY_DATA; do
    if [ -f "$DATASUBDIR/$name" ]; then
      run_at "$DATASUBDIR" rm -f "$DATASUBDIR/$name"
      removed="$removed  nselib/data/$name
"
    fi
  done
  [ -n "$removed" ] && printf '%s' "$removed"
  return 0
}

if [ "$ACTION" = "uninstall" ]; then
  say "Removing nmap-vulners from $DATADIR"
  for name in $SCRIPTS; do
    [ -f "$SCRIPTDIR/$name" ] \
      && run_at "$SCRIPTDIR" rm -f "$SCRIPTDIR/$name" \
      && say "  scripts/$name"
  done
  remove_legacy
  update_db
  say "Done."
  exit 0
fi

run_at "$DATADIR" mkdir -p "$SCRIPTDIR" "$DATASUBDIR"

# In a checkout the files are next to this script; otherwise fetch them.
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd || echo "")
SOURCE="$HERE"

if [ -z "$HERE" ] || [ ! -f "$HERE/vulners.nse" ]; then
  TMP=$(mktemp -d)
  trap 'rm -rf "$TMP"' EXIT INT TERM
  say "Downloading nmap-vulners ($REF)"
  for name in $SCRIPTS $DATA; do
    fetch "$REPO_RAW/$REF/$name" "$TMP/$name"
  done
  # A ref that still carries 1.x answers with a 1.x vulners.nse, which this
  # installer would then put in place while deleting the two data files that
  # release cannot run without - a downgrade to something broken, silently.
  # 2.0 fetches its dictionaries at scan time, and the line naming where from
  # is what tells the two apart.
  if ! grep -q '^local CATALOG_BASE' "$TMP/vulners.nse"; then
    die "$REF does not carry the 2.x script; nothing was installed"
  fi
  SOURCE="$TMP"
fi

say "Installing into $DATADIR"
for name in $SCRIPTS; do
  # nmap ships its own vulners.nse, and a distribution package may have put an
  # older copy of any of these here. Replacing them is the point: leave one
  # behind and nmap keeps running it instead of what was just installed.
  note=""
  [ -f "$SCRIPTDIR/$name" ] && note="  (replacing the existing copy)"
  run_at "$SCRIPTDIR" cp -f "$SOURCE/$name" "$SCRIPTDIR/$name"
  say "  scripts/$name$note"
done
legacy=$(remove_legacy)
if [ -n "$legacy" ]; then
  say ""
  say "Removed the 1.x files this release replaces:"
  # Command substitution ate the trailing newline; put one back so the next
  # message does not run into the last path.
  printf '%s\n' "$legacy"
fi

say "Updating the script database"
update_db

# Prove the installation rather than announce it. Checking that the name
# resolves is not enough: nmap ships a vulners.nse of its own, so the question
# is *which* file it resolves to.
if [ "$MODE" = "system" ]; then
  resolved=$(nmap -d2 --script-help vulners 2>/dev/null |
             sed -n 's|^Fetchfile found \(.*/scripts/vulners\.nse\)$|\1|p' |
             head -n 1)
else
  resolved=$(NMAPDIR="$DATADIR" nmap -d2 --script-help vulners 2>/dev/null |
             sed -n 's|^Fetchfile found \(.*/scripts/vulners\.nse\)$|\1|p' |
             head -n 1)
fi

[ -n "$resolved" ] \
  || die "the files were copied but nmap does not list them; check $SCRIPTDIR"

resolved_dir=$(cd "$(dirname "$resolved")" && pwd)
if [ "$resolved_dir/vulners.nse" != "$SCRIPTDIR/vulners.nse" ]; then
  say ""
  say "warning: nmap resolves 'vulners' to $resolved,"
  say "         not to the copy just installed in $SCRIPTDIR."
  if [ "$MODE" != "system" ]; then
    say "         Set NMAPDIR=\"$DATADIR\" so this one wins, or install"
    say "         system-wide."
  fi
fi

say ""
installed_version=$(sed -n 's/^local api_version = "\(.*\)"$/\1/p' \
  "$SCRIPTDIR/vulners.nse" | head -n 1)
say "Installed. vulners.nse $installed_version is in place. Try it:"
if [ "$MODE" = "system" ]; then
  say "  nmap -sV --script vulners scanme.nmap.org"
else
  say "  export NMAPDIR=\"$DATADIR\"        # add this to your shell profile"
  say "  nmap -sV --script vulners scanme.nmap.org"
fi
offer_key_entry

say ""
say "It works without an API key. A free key adds more detail per finding and"
say "lets it identify software the free lookup cannot name:"
say "  https://vulners.com/userinfo   (register at https://vulners.com/ first)"
