#!/usr/bin/env bash
# happyhacks-deploy: pull the latest code from GitHub and put it live.
#
#   sudo happyhacks-deploy      (installed by deploy/cloudpanel/install.sh; works from any folder)
#
# Finds the app (/home/<site user>/happyhacks), makes sure the site user can read the GitHub repository
# (deploy key, known GitHub host key, SSH remote), pulls as the site user, then reruns install.sh.
# Settings: APP=/path/to/happyhacks  SITE_USER=<user>
set -euo pipefail

# GitHub's published Ed25519 host key (docs.github.com, "GitHub's SSH key fingerprints")
GITHUB_HOST_KEY='github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl'

APP="${APP:-}"
if [ -z "$APP" ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
  h="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
  [ -n "$h" ] && [ -d "$h/happyhacks/.git" ] && APP="$h/happyhacks"
fi
if [ -z "$APP" ]; then
  found=()
  for d in /home/*/happyhacks; do [ -f "$d/wsgi.py" ] && [ -d "$d/.git" ] && [ "$(stat -c %U "$d")" != root ] && found+=("$d"); done
  if [ "${#found[@]}" -gt 1 ]; then echo "Found more than one app folder (${found[*]}). Run with APP=/home/<site user>/happyhacks."; exit 1; fi
  APP="${found[0]:-}"
fi
[ -n "$APP" ] && [ -d "$APP/.git" ] || { echo "Can't find the happyhacks Git clone (looked for /home/*/happyhacks). Run with APP=/path/to/happyhacks."; exit 1; }
SITE_USER="${SITE_USER:-$(stat -c %U "$APP")}"

if [ "$(id -u)" -ne 0 ]; then
  exec sudo APP="$APP" SITE_USER="$SITE_USER" bash "$(readlink -f "$0")" "$@"
fi
if [ "$SITE_USER" = root ]; then
  echo "$APP belongs to root, but it should belong to the CloudPanel site user. Fix with:"
  echo "    chown -R <site user>: $APP"
  exit 1
fi
HOME_DIR="$(getent passwd "$SITE_USER" | cut -d: -f6)"
GROUP="$(id -gn "$SITE_USER")"
SSH_DIR="$HOME_DIR/.ssh"
KEY="$SSH_DIR/happyhacks_deploy"
as_user() { runuser -u "$SITE_USER" -- env HOME="$HOME_DIR" "$@"; }
echo "App: $APP   site user: $SITE_USER"

remote="$(as_user git -C "$APP" remote get-url origin 2>/dev/null || true)"
case "$remote" in
  https://github.com/*)
    path="${remote#https://github.com/}"; path="${path%.git}"
    as_user git -C "$APP" remote set-url origin "happyhacks-github:$path.git"
    remote="happyhacks-github:$path.git"; echo "Switched the Git remote to $remote" ;;
  git@github.com:*)
    path="${remote#git@github.com:}"
    as_user git -C "$APP" remote set-url origin "happyhacks-github:$path"
    remote="happyhacks-github:$path"; echo "Switched the Git remote to $remote" ;;
esac

if [[ "$remote" == happyhacks-github:* ]]; then
  install -d -o "$SITE_USER" -g "$GROUP" -m 700 "$SSH_DIR"
  NEW_KEY=""
  if [ ! -f "$KEY" ]; then
    as_user ssh-keygen -q -t ed25519 -N "" -f "$KEY" -C "happyhacks deploy ($SITE_USER@$(hostname))"
    NEW_KEY=1
  fi
  chown "$SITE_USER:$GROUP" "$KEY" "$KEY.pub"; chmod 600 "$KEY"

  # A host alias, so this key doesn't collide with another app's deploy key (GitHub allows one repo per deploy key)
  if ! grep -qs '^Host happyhacks-github' "$SSH_DIR/config"; then
    printf '\nHost happyhacks-github\n  HostName github.com\n  User git\n  IdentityFile %s\n  IdentitiesOnly yes\n' "$KEY" >> "$SSH_DIR/config"
  fi
  chown "$SITE_USER:$GROUP" "$SSH_DIR/config"; chmod 600 "$SSH_DIR/config"

  if ! grep -qsF "$GITHUB_HOST_KEY" "$SSH_DIR/known_hosts"; then
    echo "$GITHUB_HOST_KEY" >> "$SSH_DIR/known_hosts"
  fi
  chown "$SITE_USER:$GROUP" "$SSH_DIR/known_hosts"; chmod 644 "$SSH_DIR/known_hosts"

  out="$(as_user ssh -o BatchMode=yes -o ConnectTimeout=15 -T happyhacks-github 2>&1 || true)"
  if ! grep -q 'successfully authenticated' <<<"$out"; then
    repo="${remote#happyhacks-github:}"; repo="${repo%.git}"
    echo
    [ -n "$NEW_KEY" ] && echo "Made a new deploy key for $SITE_USER." || echo "GitHub doesn't accept $SITE_USER's deploy key yet (${out:0:120})."
    echo "Add it on GitHub: https://github.com/$repo/settings/keys  >  Add deploy key  (leave write access off). The key:"
    echo
    echo "    $(cat "$KEY.pub")"
    echo
    echo "Then run this again:  sudo happyhacks-deploy"
    exit 1
  fi
  echo "GitHub access OK"
fi

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
say "git pull"
as_user git -C "$APP" pull --ff-only
SITE_USER="$SITE_USER" SKIP_APT="${SKIP_APT:-1}" bash "$APP/deploy/cloudpanel/install.sh"
