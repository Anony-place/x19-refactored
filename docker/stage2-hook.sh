#!/bin/sh
# s6-overlay stage2 hook — runs as root after the supervision tree is
# up but before user services start. Handles UID/GID remap, volume
# chown, config seeding, and skills sync.
#
# Per-service privilege drop happens inside each service's `run` script
# (and in main-wrapper.sh) via s6-setuidgid, not here.
#
# Wired into the image as /etc/cont-init.d/01-x19-setup by the
# Dockerfile. The shim at docker/entrypoint.sh forwards to this script
# so external references to docker/entrypoint.sh still work.
#
# NB: cont-init.d scripts run with no arguments — the user's CMD args
# are NOT visible here. That's fine: we use Architecture B (s6-overlay
# main-program model), so main-wrapper.sh runs the CMD with full
# stdin/stdout/stderr access and handles arg parsing there.

set -eu

X19_HOME="${X19_HOME:-/opt/data}"
INSTALL_DIR="/opt/x19"

# Drop to x19 via s6-setuidgid, but skip it when already non-root.
as_x19() { [ "$(id -u)" = 0 ] || { "$@"; return; }; s6-setuidgid x19 "$@"; }

# --- Reject the unsupported `docker run --user <uid>:<gid>` start ---
# Detect the case where the container was launched with `--user` pinned to an
# arbitrary host UID (the classic `--user $(id -u):$(id -g)` invocation people
# used in the tini era to make container-written files match their host user).
#
# Under s6-overlay this no longer works: the bootstrap (UID remap, data-volume
# ownership, config seeding) requires root, and it is skipped when the container
# starts non-root. The baked install tree under /opt/x19 is intentionally
# root-owned and non-writable; mutable runtime state must live under
# $X19_HOME. An arbitrary `--user` UID therefore cannot repair or populate
# the data volume, and startup fails with EACCES. See #34837 for the
# supervision-tree side of this.
#
# The supported way to match host-side ownership is to start as root (the image
# default) and pass X19_UID/X19_GID — or the PUID/PGID aliases — which the
# remap block below consumes via usermod/groupmod + targeted chown. That gives
# the exact same outcome (files owned by your host UID) without breaking s6.
#
# preinit runs setuid-root (euid=0) but cont-init.d hooks run with the real UID
# the container was started as, so `id -u` here is the host UID (e.g. 1000), and
# `id -u x19` is the unremapped build UID (10000) because no root-only remap
# could run. root starts (id -u = 0) and the normal supervised drop to the
# x19 UID are both unaffected.
cur_uid="$(id -u)"
if [ "$cur_uid" != 0 ] && [ "$cur_uid" != "$(id -u x19)" ]; then
    cat >&2 <<EOF
[stage2] ERROR: container started with --user $cur_uid (an arbitrary, non-x19 UID).

This is not supported under the s6-overlay image. The container bootstrap
(UID remap, data-volume ownership, config seeding) needs to start as root,
and the baked /opt/x19 install tree is intentionally root-owned and
non-writable, so a pinned --user UID cannot repair startup state — startup
will fail.

To make container-written files match your HOST user, DON'T use --user.
Start the container as root (the default) and pass your host UID/GID instead:

    docker run -e X19_UID=\$(id -u) -e X19_GID=\$(id -g) ...

NAS users (Synology / unRAID / UGOS) can use the PUID/PGID aliases:

    docker run -e PUID=\$(id -u) -e PGID=\$(id -g) ...

The image remaps the x19 user to that UID/GID at boot and chowns the data
volume accordingly, so files land owned by your host user — the same outcome
--user was being used for, without breaking the supervision tree.
EOF
    exit 1
fi

# --- Bootstrap X19_HOME as root ---
# Create the directory (and any missing parents) while we still have root
# privileges so the chown checks below see real metadata and the later
# `s6-setuidgid x19 mkdir -p` block doesn't EACCES on root-owned
# ancestors. Without this, custom X19_HOME paths whose parents only
# root can create (e.g. `X19_HOME=/home/x19/.x19` in a Compose
# file, or any path under a fresh / not pre-populated by the image)
# fail on first boot with `mkdir: cannot create directory '/...': Permission
# denied` and the cont-init hook exits non-zero. Idempotent — `mkdir -p`
# is a no-op if the dir already exists. (#18482, salvages #18488)
mkdir -p "$X19_HOME"

# Numeric UID/GID validation: must be digits only, non-root, 1-65534.
# NAS hosts such as Unraid commonly use low non-root IDs (99:100).
validate_uid_gid() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
        *) [ "$1" -ge 1 ] && [ "$1" -le 65534 ] ;;
    esac
}

# --- UID/GID remap ---
# Accept PUID/PGID as aliases for X19_UID/X19_GID.  NAS users (UGOS,
# Synology, unRAID) expect the LinuxServer.io PUID/PGID convention and
# bind-mount /opt/data from a host directory owned by their own UID; without
# this alias those vars are silently ignored and the s6-setuidgid drop to
# UID 10000 leaves the runtime unable to read the volume.  X19_UID/
# X19_GID still win when both are set.  See #15290, salvages #25872.
X19_UID="${X19_UID:-${PUID:-}}"
X19_GID="${X19_GID:-${PGID:-}}"

if [ -n "${X19_UID:-}" ] && validate_uid_gid "$X19_UID" && [ "$X19_UID" != "$(id -u x19)" ]; then
    echo "[stage2] Changing x19 UID to $X19_UID"
    usermod -u "$X19_UID" x19
fi
if [ -n "${X19_GID:-}" ] && validate_uid_gid "$X19_GID" && [ "$X19_GID" != "$(id -g x19)" ]; then
    echo "[stage2] Changing x19 GID to $X19_GID"
    # -o allows non-unique GID (e.g. macOS GID 20 "staff" may already
    # exist as "dialout" in the Debian-based container image).
    groupmod -o -g "$X19_GID" x19 2>/dev/null || true
fi

# --- Docker socket group membership (docker-in-docker / DooD) ---
# When the user bind-mounts the host Docker daemon socket
# (`-v /var/run/docker.sock:/var/run/docker.sock`) to use the `docker`
# terminal backend from inside the container, the socket is owned by the
# host's `docker` group (or root). The supervised x19 user (UID 10000)
# is not a member of any group that matches the socket's GID, so every
# `docker` invocation EACCES'es and `check_terminal_requirements()` fails.
# See #16703.
#
# Granting the supp group via `docker run --group-add <gid>` alone is
# NOT sufficient with our s6-setuidgid privilege drop: s6-setuidgid (and
# gosu, the older shim) calls initgroups() for the target user, which
# rebuilds the supplementary group list from /etc/group. Without an
# /etc/group entry whose GID matches the socket, the kernel-granted
# supp group is silently wiped between PID 1 and the dropped process.
# Confirmed empirically: `--group-add 998` alone leaves the dropped
# x19 process with `Groups: 10000` (998 gone); after this hook adds
# the entry, the dropped process has `Groups: 998 10000` as expected.
#
# Fix: detect the socket's GID at boot and ensure /etc/group has a
# matching entry that includes x19. Idempotent across container
# restarts. Skipped silently when no socket is bind-mounted.
#
# Handles the awkward corner cases:
#   - socket owned by GID 0 (root) — some Podman setups; usermod -aG root
#   - socket GID already used by a known container group (e.g. tty=5):
#     reuse that group's name rather than creating a duplicate
#   - x19 is already a member of the right group (idempotent restart)
#   - chown/groupadd failures under rootless containers — non-fatal
for sock in /var/run/docker.sock /run/docker.sock; do
    [ -S "$sock" ] || continue
    sock_gid=$(stat -c '%g' "$sock" 2>/dev/null) || continue
    [ -n "$sock_gid" ] || continue
    # Already a member? Nothing to do.
    if id -G x19 2>/dev/null | tr ' ' '\n' | grep -qx "$sock_gid"; then
        echo "[stage2] x19 already in group $sock_gid for $sock"
        break
    fi
    # Resolve or create a group name for this GID.
    sock_group=$(getent group "$sock_gid" 2>/dev/null | cut -d: -f1)
    if [ -z "$sock_group" ]; then
        sock_group="hostdocker"
        if ! groupadd -g "$sock_gid" "$sock_group" 2>/dev/null; then
            echo "[stage2] Warning: groupadd -g $sock_gid $sock_group failed; skipping docker socket group setup"
            break
        fi
        echo "[stage2] Created group $sock_group (GID $sock_gid) for Docker socket"
    fi
    if usermod -aG "$sock_group" x19 2>/dev/null; then
        echo "[stage2] Added x19 to group $sock_group (GID $sock_gid) for $sock"
    else
        echo "[stage2] Warning: usermod -aG $sock_group x19 failed; docker backend may fail with EACCES"
    fi
    break
done

# --- Fix ownership of data volume ---
# When X19_UID is remapped or the top-level $X19_HOME isn't owned by
# the runtime x19 UID, restore ownership to x19 — but ONLY for the
# directories x19 actually writes to. The full $X19_HOME may be a
# host-mounted bind containing unrelated user files; `chown -R` would
# silently destroy host ownership of those (see issue #19788).
#
# The canonical list of x19-owned subdirs is the same one the s6-setuidgid
# mkdir -p block below seeds. Keep them in sync if the seed list changes.
actual_x19_uid=$(id -u x19)

path_has_symlink_component() {
    path="$1"
    root="${2:-$X19_HOME}"
    while [ -n "$path" ] && [ "$path" != "/" ]; do
        if [ -L "$path" ]; then
            return 0
        fi
        if [ "$path" = "$root" ]; then
            break
        fi
        parent="$(dirname "$path")"
        if [ "$parent" = "$path" ]; then
            break
        fi
        path="$parent"
    done
    return 1
}

refuse_symlinked_path() {
    action="$1"
    target="$2"
    if path_has_symlink_component "$target"; then
        echo "[stage2] Warning: refusing $action through symlinked path $target — continuing"
        return 0
    fi
    return 1
}

chown_x19_tree() {
    target="$1"
    if refuse_symlinked_path "recursive chown" "$target"; then
        return 0
    fi
    chown -R x19:x19 "$target" 2>/dev/null || \
        echo "[stage2] Warning: chown $target failed (rootless container?) — continuing"
}

tree_has_non_x19_owner() {
    target="$1"
    find "$target" \( ! -user x19 -o ! -group x19 \) -print -quit 2>/dev/null | grep -q .
}

needs_chown=false
if [ "$(stat -c %u "$X19_HOME" 2>/dev/null)" != "$actual_x19_uid" ]; then
    needs_chown=true
fi
if [ "$needs_chown" = true ]; then
    echo "[stage2] Fixing ownership of $X19_HOME (targeted) to x19 ($actual_x19_uid)"
    # In rootless Podman the container's "root" is mapped to an
    # unprivileged host UID — chown will fail. That's fine: the volume
    # is already owned by the mapped user on the host side.
    #
    # Top-level $X19_HOME: chown the directory itself (not its contents)
    # so x19 can mkdir new subdirs but bind-mounted host files keep
    # their existing ownership.
    if refuse_symlinked_path "chown" "$X19_HOME"; then
        :
    else
        chown x19:x19 "$X19_HOME" 2>/dev/null || \
            echo "[stage2] Warning: chown $X19_HOME failed (rootless container?) — continuing"
    fi
    # X19-owned subdirs: recursive chown is safe here because these are
    # created and managed exclusively by x19 (see the s6-setuidgid mkdir
    # -p block below for the canonical list).
    for sub in cron sessions logs hooks memories skills skins plans workspace home profiles pairing platforms/pairing lazy-packages; do
        if [ -e "$X19_HOME/$sub" ] && tree_has_non_x19_owner "$X19_HOME/$sub"; then
            chown_x19_tree "$X19_HOME/$sub"
        fi
    done
fi

# --- Immutable install tree ---
# Do not chown runtime code or dependency trees under $INSTALL_DIR back to the
# x19 user. Hosted/container instances keep mutable state under
# $X19_HOME (/opt/data) and run with PYTHONDONTWRITEBYTECODE plus
# X19_DISABLE_LAZY_INSTALLS=1. Keeping /opt/x19 root-owned and
# non-writable prevents an agent session from self-modifying the installed
# source, venv, TUI bundle, or node_modules and bricking the gateway.
#
# Lazy-installable optional backends (Firecrawl, Exa, Feishu, etc.) cannot
# install into the sealed venv, so they are redirected to the writable
# $X19_HOME/lazy-packages dir on the data volume (Dockerfile sets
# X19_LAZY_INSTALL_TARGET). That dir is appended to the END of sys.path,
# so a package installed there can only ADD modules — it can never shadow or
# break a core module, which is what keeps the sealed-venv guarantee intact
# even though installs are re-enabled. The dir is seeded + chowned to x19
# in the mkdir/chown blocks above so first-use installs succeed as the
# unprivileged runtime user, and it persists across container recreates /
# image updates (an ABI stamp wipes it if a rebuild bumps the interpreter).

# Always reset ownership of $X19_HOME/profiles to x19 on every
# boot. Profile dirs and files can land owned by root when commands
# are invoked via `docker exec <container> x19 …` (which defaults
# to root unless `-u` is passed), and that breaks the cont-init
# reconciler (02-reconcile-profiles) which runs as x19 and walks
# the profiles dir. Skip the recursive walk when the tree is already
# owned correctly so warm boots do not rescan huge profile caches.
# Idempotent; skipped on rootless containers where chown would fail.
if [ -d "$X19_HOME/profiles" ] && tree_has_non_x19_owner "$X19_HOME/profiles"; then
    chown_x19_tree "$X19_HOME/profiles"
fi

# Always reset ownership of $X19_HOME/cron on every boot for the same
# docker-exec/root-write reason as profiles/. The cron scheduler state
# (jobs.json) must stay readable by the unprivileged x19 runtime even
# after root-context maintenance commands or scheduler writes. Skip the
# recursive walk when the tree is already owned correctly (same warm-boot
# gate as profiles/).
if [ -d "$X19_HOME/cron" ] && tree_has_non_x19_owner "$X19_HOME/cron"; then
    chown_x19_tree "$X19_HOME/cron"
fi

# Always ensure logs/gateways is x19-owned (#45258). Formerly healed by
# restartable gateway log/run chown — removed due to symlink TOCTOU
# (CWE-59/367). The targeted data-volume chown above only runs when the
# top-level $X19_HOME is mis-owned, so a warm volume with x19-owned
# X19_HOME but root-owned logs/gateways would otherwise leave
# s6-setuidgid x19 mkdir failing with Permission denied. Non-recursive:
# profile leaf dirs are each created/owned by their own log/run as x19.
if [ -d "$X19_HOME/logs/gateways" ]; then
    if refuse_symlinked_path "chown" "$X19_HOME/logs/gateways"; then
        :
    else
        chown x19:x19 "$X19_HOME/logs/gateways" 2>/dev/null || true
    fi
fi

# Always reset ownership of pairing data on every boot, same docker-exec/
# root-write reason as profiles/ and cron/. `docker exec <container>
# x19 pairing approve …` defaults to uid=0 and writes 0600 root-owned
# approval files that the unprivileged x19 gateway cannot read,
# silently leaving the approved user unauthorized (#10270). The targeted
# data-volume chown above only runs when the top-level $X19_HOME is
# mis-owned, so warm boots skip it — this block makes a container restart
# self-heal. Tiny directory (a handful of small JSON files), so even the
# ownership pre-scan is negligible; gated for consistency with profiles/
# and cron/.
if [ -d "$X19_HOME/platforms/pairing" ] && tree_has_non_x19_owner "$X19_HOME/platforms/pairing"; then
    chown_x19_tree "$X19_HOME/platforms/pairing"
fi
# Legacy location (pre-consolidated layout).
if [ -d "$X19_HOME/pairing" ] && tree_has_non_x19_owner "$X19_HOME/pairing"; then
    chown_x19_tree "$X19_HOME/pairing"
fi

# Reset ownership of x19-owned top-level state files on every boot.
# The targeted data-volume chown above only covers x19-owned
# *subdirectories*; loose state files living directly under $X19_HOME
# are missed. When those files are created or rewritten by
# `docker exec <container> x19 …` (root unless `-u` is passed) they
# land root-owned, and the unprivileged x19 runtime then hits
# PermissionError on next startup (e.g. gateway.lock / state.db /
# auth.json), producing a gateway restart loop.
#
# We use an explicit allowlist rather than a blanket `find -user root`
# sweep so host-owned files in a bind-mounted $X19_HOME are never
# touched — same targeted-ownership contract as the subdir chown above
# (issue #19788, PR #19795). The list mirrors the top-level *file*
# entries of x19_cli.profile_distribution.USER_OWNED_EXCLUDE plus the
# runtime lock files; keep them in sync if that set changes.
for f in \
    auth.json auth.lock .env \
    state.db state.db-shm state.db-wal \
    x19_state.db \
    response_store.db response_store.db-shm response_store.db-wal \
    gateway.pid gateway.lock gateway_state.json processes.json \
    active_profile; do
    if [ -e "$X19_HOME/$f" ]; then
        if refuse_symlinked_path "chown" "$X19_HOME/$f"; then
            :
        else
            chown x19:x19 "$X19_HOME/$f" 2>/dev/null || true
        fi
    fi
done

# --- config.yaml permissions ---
# Ensure config.yaml is readable by the x19 runtime user even if it
# was edited on the host after initial ownership setup.
if [ -f "$X19_HOME/config.yaml" ]; then
    if refuse_symlinked_path "chown/chmod" "$X19_HOME/config.yaml"; then
        :
    else
        chown x19:x19 "$X19_HOME/config.yaml" 2>/dev/null || true
        chmod 640 "$X19_HOME/config.yaml" 2>/dev/null || true
    fi
fi

# --- Seed directory structure as x19 user ---
# Run as x19 via s6-setuidgid so dirs end up owned correctly (matters
# under rootless Podman where chown back to root would fail).
#
# Use direct `mkdir -p` invocation (no `sh -c "..."` wrapper) so the
# shell isn't a second interpreter — defends against $X19_HOME values
# containing shell metacharacters. PR #30136 review item O2.
as_x19 mkdir -p \
    "$X19_HOME/backups" \
    "$X19_HOME/cron" \
    "$X19_HOME/sessions" \
    "$X19_HOME/logs" \
    "$X19_HOME/logs/gateways" \
    "$X19_HOME/hooks" \
    "$X19_HOME/memories" \
    "$X19_HOME/skills" \
    "$X19_HOME/skins" \
    "$X19_HOME/plans" \
    "$X19_HOME/workspace" \
    "$X19_HOME/home" \
    "$X19_HOME/pairing" \
    "$X19_HOME/platforms/pairing" \
    "$X19_HOME/lazy-packages"

# --- Install-method stamp ---
# The 'docker' stamp is baked into the immutable install tree at
# /opt/x19/.install_method (see Dockerfile), NOT written here into
# $X19_HOME. detect_install_method() reads the code-scoped stamp first.
#
# Why we no longer stamp $X19_HOME: it is a shared DATA volume, commonly
# bind-mounted from the host (~/.x19:/opt/data) and sometimes shared with a
# host-side Desktop/CLI install. Stamping 'docker' here clobbered that host
# install's marker, so its in-app updater read 'docker' and refused to run
# 'x19 update'. To heal homes already poisoned by older images, remove a
# stale 'docker' stamp from $X19_HOME if one is present (the host install's
# own installer re-creates its code-scoped stamp; a genuine container relies on
# the baked /opt/x19 stamp, so deleting the data-dir copy is safe).
if [ -f "$X19_HOME/.install_method" ]; then
    stamped="$(tr -d '[:space:]' < "$X19_HOME/.install_method" 2>/dev/null || true)"
    if [ "$stamped" = "docker" ]; then
        rm -f "$X19_HOME/.install_method" 2>/dev/null || true
    fi
fi

# --- Seed config files (only on first boot) ---
seed_one() {
    dest=$1
    src=$2
    if [ ! -f "$X19_HOME/$dest" ] && [ -f "$INSTALL_DIR/$src" ]; then
        if refuse_symlinked_path "seed" "$X19_HOME/$dest"; then
            :
        else
            as_x19 cp "$INSTALL_DIR/$src" "$X19_HOME/$dest"
        fi
    fi
}
seed_one ".env" ".env.example"
seed_one "config.yaml" "cli-config.yaml.example"
seed_one "SOUL.md" "docker/SOUL.md"

# --- Ensure a gateway api_server key exists (loopback control plane) ---
# The gateway's aiohttp api_server refuses to start without a strong
# API_SERVER_KEY (>=16 chars; startup guard in gateway/platforms/api_server.py).
# Hosted deployments need that listener on loopback so the dashboard — the
# container's only public HTTP door — can forward Chronos cron fires into the
# GATEWAY process, where the live platform adapters (relay, E2EE) live. The
# cron-fire route itself is NAS-JWT-authed, not key-authed; the key gates the
# rest of the api_server surface. Generate once, persist in .env (mounted
# volume), never overwrite an operator-provided value. Loopback-only: the
# default bind host is 127.0.0.1 and the Fly service only exposes the
# dashboard's port, so this listener is never publicly reachable.
#
# CREATE .env when it is missing rather than requiring it to exist (OOF-285):
# the first-boot seed above depends on /opt/x19/.env.example being present
# in the image, and when it isn't (the .dockerignore excluded it for a long
# stretch of releases) seed_one is a silent no-op, no .env ever exists, this
# keygen never ran, the api_server never started, and every scheduled cron
# fire on the instance was silently lost. The key must not depend on the
# example-file seed having worked.
#
# OPERATOR-PROVIDED KEYS WIN: if the container environment already carries
# API_SERVER_KEY (documented `docker run -e API_SERVER_KEY=...` flow), do
# not generate one. X19 loads $X19_HOME/.env with override=True, so
# a generated key written here would silently SHADOW the operator's env
# key and 401 every client still using the supplied credential.
if [ -n "${API_SERVER_KEY:-}" ]; then
    if [ -f "$X19_HOME/.env" ] && grep -q '^API_SERVER_KEY=..*' "$X19_HOME/.env" 2>/dev/null; then
        echo "[stage2] Warning: API_SERVER_KEY is set in both the container environment and $X19_HOME/.env — the .env value wins at runtime (loaded with override=True)"
    else
        # The env key is the effective key on this boot (no .env key wins
        # over it). The api_server startup guard refuses keys shorter than
        # 16 chars; since this branch skips generation, a weak operator key
        # means the server stays DOWN (cron fires lost), not just 401s.
        # Warn where the operator will look — the boot log. Checked only in
        # this branch: when a strong .env key wins at runtime, the warning
        # would be false (the server does start).
        if [ "${#API_SERVER_KEY}" -lt 16 ]; then
            echo "[stage2] Warning: container-provided API_SERVER_KEY is shorter than 16 characters — the gateway api_server will refuse to start (cron fires unavailable). Generate a strong secret, e.g. \`openssl rand -hex 32\`."
        fi
        # A stale empty `API_SERVER_KEY=` line (left by an old seed) would
        # clobber the container-provided key at runtime: .env is loaded with
        # override=True and python-dotenv sets the empty string, which fails
        # the api_server's startup guard — the exact silent-cron-loss symptom
        # this hook exists to prevent. Drop it so the operator key wins.
        if [ -f "$X19_HOME/.env" ] && ! refuse_symlinked_path "clean" "$X19_HOME/.env"; then
            sed -i '/^API_SERVER_KEY=$/d' "$X19_HOME/.env" 2>/dev/null || true
        fi
        echo "[stage2] API_SERVER_KEY provided via container environment — skipping generation"
    fi
elif ! grep -q '^API_SERVER_KEY=..*' "$X19_HOME/.env" 2>/dev/null; then
    if refuse_symlinked_path "append" "$X19_HOME/.env"; then
        :
    else
        if [ ! -f "$X19_HOME/.env" ]; then
            # Create an empty, owner-only .env so the append below (and any
            # later runtime save_env_value writes) have a durable target.
            # Created under a restrictive umask so the file is 0600 from the
            # first instant — no touch→chmod window, and no dependence on a
            # silenced chmod succeeding. The chown/chmod block below still
            # re-tightens perms every boot.
            (umask 077 && as_x19 touch "$X19_HOME/.env") 2>/dev/null || true
        fi
        if [ -f "$X19_HOME/.env" ]; then
            _gen_key=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
            if [ -n "$_gen_key" ]; then
                # Drop an empty assignment line if the seed left one behind,
                # then append the generated key. The append is guarded: on a
                # read-only volume / full disk it must degrade to the warning
                # below, not abort the whole stage2 hook under `set -e`.
                sed -i '/^API_SERVER_KEY=$/d' "$X19_HOME/.env" 2>/dev/null || true
                if printf 'API_SERVER_KEY=%s\n' "$_gen_key" >> "$X19_HOME/.env" 2>/dev/null; then
                    echo "[stage2] Generated API_SERVER_KEY for the loopback gateway api_server"
                else
                    echo "[stage2] Warning: could not write API_SERVER_KEY to $X19_HOME/.env (read-only volume?) — gateway api_server (cron fires) will be unavailable"
                fi
            fi
            unset _gen_key
        else
            echo "[stage2] Warning: could not create $X19_HOME/.env — gateway api_server (cron fires) will be unavailable"
        fi
    fi
fi

# --- Sync deploy-injected Nous routing overrides into every profile .env ---
# Under multiplex, x19_cli.auth_nous reads X19_PORTAL_BASE_URL (or its
# NOUS_PORTAL_BASE_URL alias) and NOUS_INFERENCE_BASE_URL through the profile
# secret scope (agent.secret_scope.get_secret, #108319 / #111809), built from
# <profile>/.env with no os.environ fallback — a value that lives only in the
# container env is invisible on every routed turn, the Portal URL heals to
# production and a non-production login is quarantined. The deploy therefore
# carries the value into $X19_HOME/.env and every profiles/*/.env: the
# container wins over a stale line, an already-correct line is left alone, and
# lines written here carry a marker so a boot WITHOUT the variable removes them
# again (a hand-set line is never touched). Known gap: a profile created while the container
# runs is synced on the next boot. Interim until the managed scope
# (/etc/x19/.env) composition reverted by #111600 is restored.
_ROUTING_MARK='# stage2-managed'
# rewrite_env_var FILE NAME DROP_PATTERN [LINE]: drop the lines matching DROP_PATTERN (a BRE),
# append LINE when given. Rewritten through the existing inode (owner and mode kept — sed -i would
# re-create the file). `grep -v` exits 1 when nothing remains (fine) and 2 when the file could not
# be read (then a rewrite would wipe every other secret — refuse). A read-only volume degrades to a
# warning, never a boot abort.
rewrite_env_var() {
    _rc=0
    _rest=$(grep -v -- "$3" "$1" 2>/dev/null) || _rc=$?
    if [ "$_rc" -gt 1 ]; then
        echo "[stage2] Warning: could not read $1 — leaving $2 untouched"
        return 1
    fi
    if [ $# -ge 4 ]; then
        _rest="${_rest:+$_rest
}$4"
    fi
    if printf '%s' "${_rest:+$_rest
}" 2>/dev/null > "$1"; then
        return 0
    fi
    echo "[stage2] Warning: could not write $2 to $1 (read-only volume?) — routed turns will fall back to the production Portal"
    return 1
}
sync_routing_overrides() {
    _file="$1"
    if refuse_symlinked_path "sync" "$_file"; then
        return 0
    fi
    for _name in X19_PORTAL_BASE_URL NOUS_PORTAL_BASE_URL NOUS_INFERENCE_BASE_URL; do
        eval "_value=\${$_name:-}"
        _managed="^$_name=.* $_ROUTING_MARK\$"
        if [ -z "$_value" ]; then
            if grep -q -- "$_managed" "$_file" 2>/dev/null && rewrite_env_var "$_file" "$_name" "$_managed"; then
                echo "[stage2] Removed $_name from $_file (no longer set in the container environment)"
            fi
            continue
        fi
        _line="$_name=$_value $_ROUTING_MARK"
        if grep -qxF -- "$_line" "$_file" 2>/dev/null; then
            continue
        fi
        if [ ! -f "$_file" ] && ! (umask 077 && as_x19 touch "$_file") 2>/dev/null; then
            echo "[stage2] Warning: could not create $_file — the Nous routing overrides will not reach this profile's secret scope"
            return 0
        fi
        if rewrite_env_var "$_file" "$_name" "^$_name=" "$_line"; then
            echo "[stage2] Synced $_name from the container environment into $_file"
        fi
    done
}
sync_routing_overrides "$X19_HOME/.env"
for _profile_dir in "$X19_HOME"/profiles/*/; do
    [ -d "$_profile_dir" ] || continue
    sync_routing_overrides "${_profile_dir}.env"
done
unset _profile_dir _file _name _value _managed _line _rest _rc

# .env holds API keys and secrets — restrict to owner-only access. Applied
# unconditionally (not only on first-seed) so a host-mounted .env that was
# created with a permissive umask gets tightened on every container start.
if [ -f "$X19_HOME/.env" ]; then
    if refuse_symlinked_path "chown/chmod" "$X19_HOME/.env"; then
        :
    else
        chown x19:x19 "$X19_HOME/.env" 2>/dev/null || true
        chmod 600 "$X19_HOME/.env" 2>/dev/null || true
    fi
fi

# --- Grant the gateway access to the Fly Machines API socket (scale-to-zero) ---
# On Fly, flyd mounts the local Machines API ("flaps") unix socket at /.fly/api
# owned root:root 0755. The gateway's scale-to-zero self-suspend
# (gateway/scale_to_zero.py suspend_self) must POST to it, but the gateway runs
# as the unprivileged `x19` user — without this it gets EACCES on every
# suspend attempt and the machine can never sleep (fail-awake; verified live on
# staging 2026-08-20: "flaps suspend request failed: [Errno 13]"). This hook
# runs as root before user services (the gateway) start, so grant group access
# here. Scope note: group-write exposes the WHOLE local Machines API to the
# x19 group (any group member could e.g. stop/suspend this machine), not
# just the suspend endpoint — accepted because the agent already executes
# arbitrary user code as that same principal and the socket only controls THIS
# machine. No-op off Fly (socket absent).
if [ -S /.fly/api ]; then
    if refuse_symlinked_path "chgrp/chmod" /.fly/api; then
        :
    elif chgrp x19 /.fly/api 2>/dev/null && chmod g+w /.fly/api 2>/dev/null; then
        echo "[stage2] Granted x19 group access to the Fly Machines API socket"
    else
        echo "[stage2] Warning: could not grant group access to /.fly/api — scale-to-zero self-suspend will fail EACCES (fail-awake)"
    fi
fi

# --- Migrate persisted config schema ---
# Docker image upgrades replace the code under $INSTALL_DIR but preserve
# $X19_HOME on the mounted volume. Run the same safe, non-interactive
# config-schema migrations that `x19 update` runs for non-Docker installs,
# after first-boot seeding and before supervised gateway services start.
# Set X19_SKIP_CONFIG_MIGRATION=1 for controlled/manual migrations.
if [ -f "$X19_HOME/config.yaml" ]; then
    s6-setuidgid x19 "$INSTALL_DIR/.venv/bin/python" "$INSTALL_DIR/scripts/docker_config_migrate.py" \
        || echo "[stage2] Warning: docker_config_migrate.py failed; continuing"
fi

# auth.json: bootstrap from env on first boot only. Same semantics as the
# pre-s6 entrypoint — the [ ! -f ] guard is critical to avoid clobbering
# rotated refresh tokens on container restart.
if [ ! -f "$X19_HOME/auth.json" ] && [ -n "${X19_AUTH_JSON_BOOTSTRAP:-}" ]; then
    if refuse_symlinked_path "seed" "$X19_HOME/auth.json"; then
        :
    else
        printf '%s' "$X19_AUTH_JSON_BOOTSTRAP" > "$X19_HOME/auth.json"
        chown x19:x19 "$X19_HOME/auth.json" 2>/dev/null || true
        chmod 600 "$X19_HOME/auth.json"
    fi
fi

# auth.json: re-seed a TERMINALLY-DEAD Nous bootstrap session (self-heal).
#
# The [ ! -f ] guard above deliberately refuses to clobber an existing
# auth.json, so a container whose Nous bootstrap session took a terminal
# invalid_grant (tokens cleared, providers.nous.last_auth_error.relogin_required
# stamped) can NOT recover from a plain restart — it stays unauthenticated until
# the credential is replaced. An orchestrator that manages the container can
# supply a freshly-issued session via X19_AUTH_JSON_REBOOTSTRAP (distinct
# from the create-only *_BOOTSTRAP var); this helper swaps ONLY the
# providers.nous entry when the on-disk entry is provably terminal OR the
# orchestrator seed has a later obtained_at timestamp. The latter covers the
# stop/update/start sequence where NAS already revoked the still-healthy-looking
# local session. Older/incomparable seeds remain no-ops, so leaving the env set
# cannot roll a healthy rotated token backward. Runs as its own stdlib-only
# subprocess (no app imports) and always exits 0.
if [ -f "$X19_HOME/auth.json" ] && [ -n "${X19_AUTH_JSON_REBOOTSTRAP:-}" ]; then
    if refuse_symlinked_path "reseed" "$X19_HOME/auth.json"; then
        :
    else
        s6-setuidgid x19 "$INSTALL_DIR/.venv/bin/python" \
            "$INSTALL_DIR/scripts/docker_rebootstrap_nous_session.py" \
            "$X19_HOME/auth.json" \
            || echo "[stage2] Warning: docker_rebootstrap_nous_session.py failed; continuing"
    fi
fi

# gateway_state.json: declare the gateway's INITIAL supervised state on a
# fresh volume. Same first-boot-only env-seed pattern as auth.json above.
#
# On a blank volume there is no gateway_state.json, so the boot reconciler
# (cont-init.d/02-reconcile-profiles → container_boot.reconcile_profile_gateways)
# registers the gateway-default s6 slot but leaves it DOWN — it only
# auto-starts when the last recorded state was "running". That means a
# freshly-provisioned container comes up with the gateway down until
# someone starts it (e.g. from the dashboard). An orchestrator that
# provisions a fresh volume and wants the gateway running from first boot
# can set X19_GATEWAY_BOOTSTRAP_STATE=running; we seed the state file
# here, BEFORE 02-reconcile-profiles runs (cont-init.d scripts run in
# lexicographic order), so the reconciler sees prior_state=running and
# brings the supervised slot up on the very first boot.
#
# This is a generic container contract, not specific to any host: it seeds
# the SAME gateway_state.json the reconciler already consults, exactly as
# X19_AUTH_JSON_BOOTSTRAP seeds auth.json. The [ ! -f ] guard is the
# load-bearing part — on every subsequent boot the persisted state wins,
# so a gateway the operator deliberately stopped stays stopped across
# restarts and we never clobber real runtime state.
#
# Only a literal "running" is honoured (the sole value in the reconciler's
# _AUTOSTART_STATES); any other value is ignored so a typo can't write a
# bogus state the reconciler would treat as "no prior state" anyway.
if [ ! -f "$X19_HOME/gateway_state.json" ] && \
        [ "${X19_GATEWAY_BOOTSTRAP_STATE:-}" = "running" ]; then
    if refuse_symlinked_path "seed" "$X19_HOME/gateway_state.json"; then
        :
    else
        printf '{"gateway_state":"running"}\n' > "$X19_HOME/gateway_state.json"
        chown x19:x19 "$X19_HOME/gateway_state.json" 2>/dev/null || true
        chmod 644 "$X19_HOME/gateway_state.json"
    fi
fi

# --- Sync bundled skills ---
# Invoke the venv's python by absolute path so we don't need a `sh -c`
# wrapper to source the activate script. This is safe because
# skills_sync.py doesn't depend on any environment exports beyond what
# the python binary's own bin-stub already sets up (sys.path is rooted
# at the venv's site-packages by virtue of running .venv/bin/python).
if [ -d "$INSTALL_DIR/skills" ]; then
    as_x19 "$INSTALL_DIR/.venv/bin/python" "$INSTALL_DIR/tools/skills_sync.py" \
        || echo "[stage2] Warning: skills_sync.py failed; continuing"
fi

# --- Discover agent-browser's Chromium binary ---
# The image's Dockerfile runs `npx playwright install chromium`, which
# populates ``$PLAYWRIGHT_BROWSERS_PATH`` (=/opt/x19/.playwright) with
# a ``chromium_headless_shell-<build>/chrome-headless-shell-linux64/``
# directory. agent-browser (the runtime CLI X19 spawns for the
# browser tool) doesn't recognise this layout in its own cache scan and
# fails with "Auto-launch failed: Chrome not found" — even though the
# binary is right there (#15697).
#
# Fix: locate the binary at boot and export ``AGENT_BROWSER_EXECUTABLE_PATH``
# via /run/s6/container_environment so the `with-contenv` shebang on
# main-wrapper.sh propagates it into the supervised ``x19`` process
# and thence to agent-browser subprocesses.
#
# - Skipped when the user has already set ``AGENT_BROWSER_EXECUTABLE_PATH``
#   (lets users override with a system Chrome install).
# - Filename-matched (not path-matched): the chromium dir contains many
#   shared libraries (libGLESv2.so, libEGL.so, ...) which inherit the
#   executable bit from Playwright's tarball but are NOT browser binaries.
#   We only accept files whose basename is chrome / chromium /
#   chrome-headless-shell / headless_shell / chromium-browser. Compare
#   PR #18635's earlier ``find | grep -Ei 'chrome|chromium'`` which would
#   match the path ``.../chrome-headless-shell-linux64/libGLESv2.so`` and
#   pick a .so.
# - Quietly skipped when $PLAYWRIGHT_BROWSERS_PATH doesn't exist (e.g.
#   custom builds that strip Playwright).
if [ -z "${AGENT_BROWSER_EXECUTABLE_PATH:-}" ] && \
        [ -n "${PLAYWRIGHT_BROWSERS_PATH:-}" ] && \
        [ -d "$PLAYWRIGHT_BROWSERS_PATH" ]; then
    browser_bin=$(find "$PLAYWRIGHT_BROWSERS_PATH" -type f -executable \
        \( -name 'chrome' -o -name 'chromium' \
           -o -name 'chrome-headless-shell' -o -name 'headless_shell' \
           -o -name 'chromium-browser' \) \
        2>/dev/null | head -n 1)
    if [ -n "$browser_bin" ]; then
        echo "[stage2] Found agent-browser Chromium binary: $browser_bin"
        # Write to s6's container_environment so with-contenv picks it
        # up for all supervised services (main-x19, dashboard, etc.).
        # Idempotent: each boot overwrites with the current path.
        # Some container runtimes / s6-overlay versions do not create the
        # envdir before cont-init hooks run, so create it defensively.
        mkdir -p /run/s6/container_environment
        printf '%s' "$browser_bin" > /run/s6/container_environment/AGENT_BROWSER_EXECUTABLE_PATH
    else
        echo "[stage2] Warning: no Chromium binary under $PLAYWRIGHT_BROWSERS_PATH; browser tool may fail"
    fi
fi

echo "[stage2] Setup complete; starting user services"
