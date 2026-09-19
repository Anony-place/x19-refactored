#!/usr/bin/env bash
# Run an X19 instance in an isolated sandbox — separate X19_HOME,
# separate Electron userData, and a distinct Desktop app name so it doesn't compete
# with your main desktop instance's single-instance lock.
#
# By default the sandbox is throwaway: a temp dir is created and removed on
# exit. Use --persistent to keep the sandbox across restarts (stored under
# .x19-sandbox/ in the worktree git root).
#
# Usage:
#   scripts/dev-sandbox.sh python -m x19_cli.main
#   scripts/dev-sandbox.sh x19 desktop
#   scripts/dev-sandbox.sh electron .
#   scripts/dev-sandbox.sh -- npm run dev   # from apps/desktop/
#   scripts/dev-sandbox.sh --persistent x19 desktop
#   scripts/dev-sandbox.sh --persistent -- npm run dev
#
# Seed the sandbox X19_HOME from an existing directory (e.g. your main
# ~/.x19) so config, sessions, skills, etc. are pre-populated:
#   scripts/dev-sandbox.sh --from ~/.x19 x19 desktop
#
# Override the app name (default: X19Sandbox):
#   X19_DEV_SANDBOX_NAME=Staging scripts/dev-sandbox.sh x19 desktop
#
# Override the persistent sandbox dir name (default: .x19-sandbox):
#   X19_DEV_SANDBOX_DIR=.staging-sandbox scripts/dev-sandbox.sh --persistent x19 desktop

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

print_help() {
  cat <<'EOF'
Usage: dev-sandbox.sh [--persistent] [--from DIR] [--] <command...>

Run an X19 instance in an isolated sandbox.

Options:
  --persistent    Keep the sandbox dir across restarts (under the worktree
                  git root, in .x19-sandbox/). Without this flag the
                  sandbox is a temp dir that is removed on exit.
  --from DIR      Copy DIR into the sandbox X19_HOME as the starting
                  point (config, sessions, skills, etc.).
                  Ignored if the sandbox X19_HOME already has content
                  (e.g. reusing a --persistent sandbox) to avoid clobbering.
  --delete        Delete the existing persistent sandbox in .x19-sandbox.
  -h, --help      Show this help message.

Environment:
  X19_DEV_SANDBOX_NAME  Override the app name (default: X19Sandbox)
  X19_DEV_SANDBOX_DIR   Override the persistent dir name (default: .x19-sandbox)

Examples:
  dev-sandbox.sh x19 desktop
  dev-sandbox.sh --persistent x19 desktop
  dev-sandbox.sh --from ~/.x19 x19 desktop
  dev-sandbox.sh -- npm run dev
EOF
}

PERSISTENT=false
DELETE=false
SEED_DIR=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --persistent)
      PERSISTENT=true
      shift
      ;;
    --from)
      if [ "$#" -lt 2 ] || [[ "$2" == -* ]]; then
        echo "error: --from requires a directory argument" >&2
        exit 1
      fi
      SEED_DIR="$2"
      shift 2
      ;;
    --from=*)
      SEED_DIR="${1#--from=}"
      if [ -z "$SEED_DIR" ]; then
        echo "error: --from requires a directory argument" >&2
        exit 1
      fi
      shift
      ;;
    --delete)
      DELETE=true
      shift
      ;;
    -h|--help)
      print_help
      exit 0
      ;;
    --)
      shift
      break
      ;;
    *)
      break
      ;;
  esac
done

if [ -n "$SEED_DIR" ]; then
  if [ ! -d "$SEED_DIR" ]; then
    echo "error: --from dir '$SEED_DIR' does not exist" >&2
    exit 1
  fi
  # Resolve to absolute path so it's valid after we cd later.
  SEED_DIR="$(cd "$SEED_DIR" && pwd)"
fi

if [ "$#" -eq 0 ]; then
  print_help >&2
  exit 1
fi


SANDBOX_DIR_NAME="${X19_DEV_SANDBOX_DIR:-.x19-sandbox}"
GIT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || echo "$SCRIPT_DIR/..")"
GIT_ROOT="$(cd "$GIT_ROOT" && pwd)"
PERSISTENT_SANDBOX_ROOT="$GIT_ROOT/$SANDBOX_DIR_NAME"

if [ "$DELETE" = true ]; then
  if [ -d "$PERSISTENT_SANDBOX_ROOT" ]; then
    read -r -p "[sandbox] delete $PERSISTENT_SANDBOX_ROOT? [y/N] " REPLY
    case "$REPLY" in
      [yY]|[yY][eE][sS])
        echo "[sandbox] deleting $PERSISTENT_SANDBOX_ROOT" >&2
        rm -rf -- "$PERSISTENT_SANDBOX_ROOT"
        ;;
      *)
        echo "[sandbox] aborted" >&2
        exit 1
        ;;
    esac
  else
    echo "[sandbox] nothing to delete at $PERSISTENT_SANDBOX_ROOT" >&2
  fi
  exit 0
fi

# Derive a per-worktree app name so multiple checkouts don't collide.
# Each worktree has its own toplevel path even though they share one repo,
# so we hash that path into a short, stable suffix.
WORKTREE_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || echo "$SCRIPT_DIR/..")"
WORKTREE_ROOT="$(cd "$WORKTREE_ROOT" && pwd)"
WORKTREE_HASH="$(printf '%s' "$WORKTREE_ROOT" | cksum | cut -d' ' -f1)"
WORKTREE_NAME="$(basename "$WORKTREE_ROOT")"
DEFAULT_SANDBOX_NAME="X19Sandbox-${WORKTREE_NAME}-${WORKTREE_HASH}"

SANDBOX_NAME="${X19_DEV_SANDBOX_NAME:-$DEFAULT_SANDBOX_NAME}"

if [ "$PERSISTENT" = true ]; then
  SANDBOX_ROOT="$PERSISTENT_SANDBOX_ROOT"
else
  SANDBOX_ROOT="$(mktemp -d -t x19-sandbox.XXXXXX)"
fi

export X19_HOME="$SANDBOX_ROOT/x19-home"
export X19_DESKTOP_USER_DATA_DIR="$SANDBOX_ROOT/user-data"
export X19_DESKTOP_APP_NAME="$SANDBOX_NAME"

mkdir -p "$X19_HOME" "$X19_DESKTOP_USER_DATA_DIR"

if [ -n "$SEED_DIR" ]; then
  # Only seed when the sandbox X19_HOME is empty — avoids clobbering an
  # existing persistent sandbox on re-run.
  if [ -z "$(ls -A "$X19_HOME" 2>/dev/null)" ]; then
    echo "[sandbox] seeding X19_HOME from $SEED_DIR" >&2
    cp -a "$SEED_DIR/." "$X19_HOME/"
  else
    echo "[sandbox] --from ignored: $X19_HOME already has content" >&2
  fi
fi

echo "[sandbox] X19_HOME=$X19_HOME" >&2
echo "[sandbox] userData=$X19_DESKTOP_USER_DATA_DIR" >&2
echo "[sandbox] appName=$X19_DESKTOP_APP_NAME" >&2
if [ "$PERSISTENT" = true ]; then
  echo "[sandbox] persistent: $SANDBOX_ROOT" >&2
else
  echo "[sandbox] ephemeral (will be cleaned up on exit)" >&2
fi

if [ "$PERSISTENT" = false ]; then
  # shellcheck disable=SC2329  # invoked via trap
  cleanup() {
    chmod -R u+w "$SANDBOX_ROOT"
    rm -rf -- "$SANDBOX_ROOT"
  }
  trap cleanup EXIT
  trap 'cleanup; exit 130' INT TERM
fi

"$@"
rc=$?
exit $rc