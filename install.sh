#!/bin/sh
# Install the nmap-vulners scripts where the local nmap will find them.
#
# From a checkout:            ./install.sh
# Without one:                curl -fsSL https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/install.sh | sh
# Without root:               ./install.sh --user
# Somewhere specific:         ./install.sh --prefix /usr/local/share/nmap
# Removing it again:          ./install.sh --uninstall
#
# Other options:
#   --ref REF     install this branch or tag instead of master (download mode)
#   --help
#
# macOS, Linux, Kali, WSL - anything with a POSIX shell. Windows has install.ps1.

set -eu

REPO_RAW="https://raw.githubusercontent.com/vulnersCom/nmap-vulners"
REF="master"
PREFIX=""
MODE="system"
ACTION="install"

SCRIPTS="http-vulners-regex.nse vulners.nse vulners_enterprise.nse"
DATA="http-vulners-regex.json http-vulners-paths.txt"

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
usage() { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
  case "$1" in
    --user) MODE="user"; shift ;;
    --prefix) PREFIX="${2:-}"; [ -n "$PREFIX" ] || die "--prefix needs a directory"; MODE="prefix"; shift 2 ;;
    --ref) REF="${2:-}"; [ -n "$REF" ] || die "--ref needs a branch or tag"; shift 2 ;;
    --uninstall) ACTION="uninstall"; shift ;;
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
  reported=$(nmap -d2 --script-help nmap-vulners-install-probe 2>&1 |
             sed -n 's|^Fetchfile found \(.*\)/nse_main\.lua$|\1|p' |
             head -n 1)

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
    die "$target is not writable and sudo is not available; re-run as root or use --user"
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

if [ "$ACTION" = "uninstall" ]; then
  say "Removing nmap-vulners from $DATADIR"
  for name in $SCRIPTS; do
    [ -f "$SCRIPTDIR/$name" ] && run_at "$SCRIPTDIR" rm -f "$SCRIPTDIR/$name" && say "  scripts/$name"
  done
  for name in $DATA; do
    [ -f "$DATASUBDIR/$name" ] && run_at "$DATASUBDIR" rm -f "$DATASUBDIR/$name" && say "  nselib/data/$name"
  done
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
for name in $DATA; do
  run_at "$DATASUBDIR" cp -f "$SOURCE/$name" "$DATASUBDIR/$name"
  say "  nselib/data/$name"
done

say "Updating the script database"
update_db

# Prove the installation rather than announce it. Checking that the name
# resolves is not enough: nmap ships a vulners.nse of its own, so the question
# is *which* file it resolves to.
if [ "$MODE" = "system" ]; then
  resolved=$(nmap -d2 --script-help vulners 2>/dev/null |
             sed -n 's|^Fetchfile found \(.*/scripts/vulners\.nse\)$|\1|p' | head -n 1)
else
  resolved=$(NMAPDIR="$DATADIR" nmap -d2 --script-help vulners 2>/dev/null |
             sed -n 's|^Fetchfile found \(.*/scripts/vulners\.nse\)$|\1|p' | head -n 1)
fi

[ -n "$resolved" ] || die "the files were copied but nmap does not list them; check $SCRIPTDIR"

if [ "$(cd "$(dirname "$resolved")" && pwd)/vulners.nse" != "$SCRIPTDIR/vulners.nse" ]; then
  say ""
  say "warning: nmap resolves 'vulners' to $resolved,"
  say "         not to the copy just installed in $SCRIPTDIR."
  if [ "$MODE" != "system" ]; then
    say "         Set NMAPDIR=\"$DATADIR\" so this one wins, or install system-wide."
  fi
fi

say ""
installed_version=$(sed -n 's/^local api_version = "\(.*\)"$/\1/p' "$SCRIPTDIR/vulners.nse" | head -n 1)
say "Installed. vulners.nse $installed_version is in place. Try it:"
if [ "$MODE" = "system" ]; then
  say "  nmap -sV --script vulners scanme.nmap.org"
else
  say "  export NMAPDIR=\"$DATADIR\"        # add this to your shell profile"
  say "  nmap -sV --script vulners scanme.nmap.org"
fi
say ""
say "vulners_enterprise needs an API key from https://vulners.com :"
say "  export VULNERS_API_KEY=<token>"
say "  nmap -sV --script vulners_enterprise <target>"
