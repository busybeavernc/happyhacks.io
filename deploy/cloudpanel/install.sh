#!/usr/bin/env bash
# Install or update happyhacks.io on a CloudPanel server (same layout as zipzip).
# CloudPanel keeps control of nginx and the HTTPS certificate; this script sets up the app and its process.
#
#   1. In CloudPanel: Add Site > Python, domain happyhacks.io, App Port 9010. Note the site user it creates.
#   2. As the site user, clone the repository to /home/<site user>/happyhacks (see README), then as root:
#          sudo SITE_USER=<site user> bash /home/<site user>/happyhacks/deploy/cloudpanel/install.sh
#   3. Turn on Let's Encrypt for the site in CloudPanel (SSL/TLS tab).
#   Updates: sudo happyhacks-deploy   (checks GitHub access, git pull as the site user, then this script).
#
# Layout (all owned by the site user):
#   /home/<user>/happyhacks        app code + virtual environment + .env   (outside htdocs, so nginx never serves app files)
#   /home/<user>/logs/happyhacks   gunicorn log
#   /home/<user>/htdocs/happyhacks.io/static   copy of static/ (CloudPanel's vhost serves css/js/images from htdocs)
set -euo pipefail

SITE_USER="${SITE_USER:-}"
DOMAIN="${DOMAIN:-happyhacks.io}"
APP_PORT="${APP_PORT:-9010}"
PYTHON="${PYTHON:-python3}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "Please run as root:  sudo SITE_USER=<site user> bash deploy/cloudpanel/install.sh"; exit 1; }
[ -n "$SITE_USER" ] || { echo "Set SITE_USER to the CloudPanel site user for $DOMAIN (shown on the site's Settings page)."; exit 1; }
id -u "$SITE_USER" >/dev/null 2>&1 || { echo "There is no user '$SITE_USER'. Create the site in CloudPanel first, or check the name."; exit 1; }
[ -f "$SRC/wsgi.py" ] || { echo "Run this from the app folder (it should contain wsgi.py)."; exit 1; }

HOME_DIR="$(getent passwd "$SITE_USER" | cut -d: -f6)"
APP="$HOME_DIR/happyhacks"
LOGS="$HOME_DIR/logs/happyhacks"
GROUP="$(id -gn "$SITE_USER")"
as_user() { runuser -u "$SITE_USER" -- env HOME="$HOME_DIR" "$@"; }

if [ "${SKIP_APT:-0}" != 1 ] && ! dpkg -s python3-venv python3-pip supervisor rsync curl git >/dev/null 2>&1; then
  say "System packages (python3-venv, supervisor, git)"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq python3 python3-venv python3-pip supervisor rsync curl git >/dev/null
fi

say "Folders"
install -d -o "$SITE_USER" -g "$GROUP" -m 750 "$APP"
install -d -o "$SITE_USER" -g "$GROUP" -m 750 "$HOME_DIR/logs" 2>/dev/null || true
install -d -o "$SITE_USER" -g "$GROUP" -m 750 "$LOGS"

say "App code -> $APP"
if [ "$SRC" != "$APP" ]; then
  rsync -a --delete --exclude '.env' --exclude '.venv/' --exclude 'venv/' --exclude '__pycache__/' --exclude '.git/' "$SRC"/ "$APP"/
fi
chown -R "$SITE_USER:$GROUP" "$APP"

if [ -z "${VENV:-}" ]; then
  for d in pyenv .venv venv env; do [ -x "$APP/$d/bin/python" ] && { VENV="$APP/$d"; break; }; done
fi
VENV="${VENV:-$APP/.venv}"
say "Python environment ($VENV)"
[ -x "$VENV/bin/python" ] || as_user "$PYTHON" -m venv "$VENV"
as_user "$VENV/bin/pip" install -q --upgrade pip
as_user "$VENV/bin/pip" install -q -r "$APP/requirements.txt"

say "Settings ($APP/.env)"
if [ ! -f "$APP/.env" ]; then
  sed -e "s|^APP_PORT=.*|APP_PORT=$APP_PORT|" "$APP/.env.example" > "$APP/.env"
  echo "Created $APP/.env"
else
  echo "Keeping existing $APP/.env"
  grep -q '^APP_PORT=' "$APP/.env" || echo "APP_PORT=$APP_PORT" >> "$APP/.env"
fi
if ! grep -qE '^SECRET_KEY=.+' "$APP/.env"; then
  sed -i '/^SECRET_KEY=/d' "$APP/.env"
  echo "SECRET_KEY=$("$PYTHON" -c 'import secrets; print(secrets.token_urlsafe(48))')" >> "$APP/.env"
fi
NEW_ADMIN_PW=""
if ! grep -qE '^ADMIN_PASSWORD=.+' "$APP/.env"; then   # sign-in for /admin
  sed -i '/^ADMIN_PASSWORD=/d' "$APP/.env"
  NEW_ADMIN_PW="$("$PYTHON" -c 'import secrets; print(secrets.token_urlsafe(18))')"
  echo "ADMIN_PASSWORD=$NEW_ADMIN_PW" >> "$APP/.env"
fi
chown "$SITE_USER:$GROUP" "$APP/.env"; chmod 600 "$APP/.env"
APP_PORT="$(grep -E '^APP_PORT=' "$APP/.env" | tail -1 | cut -d= -f2-)"

say "Self-test"
( cd "$APP" && as_user env PYTHONDONTWRITEBYTECODE=1 "$VENV/bin/python" -m unittest discover -s tests -t . 2>&1 | tail -3 )

say "supervisor: program happyhacks (gunicorn on 127.0.0.1:$APP_PORT as $SITE_USER)"
sed -e "s|{{APP}}|$APP|g" -e "s|{{USER}}|$SITE_USER|g" -e "s|{{LOGS}}|$LOGS|g" -e "s|{{HOME}}|$HOME_DIR|g" -e "s|{{VENV}}|$VENV|g" \
  "$APP/deploy/cloudpanel/supervisor.conf.template" > /etc/supervisor/conf.d/happyhacks.conf
if [ -d /run/systemd/system ]; then systemctl enable --now supervisor >/dev/null 2>&1 || true
elif ! pgrep -x supervisord >/dev/null; then supervisord -c /etc/supervisor/supervisord.conf; sleep 1; fi
supervisorctl reread >/dev/null
supervisorctl update >/dev/null
supervisorctl restart happyhacks

# the "sudo happyhacks-deploy" command: a copy of deploy.sh, refreshed on every install/update
install -m 755 "$APP/deploy/cloudpanel/deploy.sh" /usr/local/sbin/happyhacks-deploy

# "Update live site" on /admin: the app's user may run exactly this one command as root, nothing else
SUDOERS_TMP="$(mktemp)"
printf '%s\n' "# written by happyhacks' install.sh: lets /admin run the deploy (happyhacks/selfupdate.py)" \
  "$SITE_USER ALL=(root) NOPASSWD: /usr/local/sbin/happyhacks-deploy" > "$SUDOERS_TMP"
if visudo -cf "$SUDOERS_TMP" >/dev/null 2>&1; then install -m 440 -o root -g root "$SUDOERS_TMP" /etc/sudoers.d/happyhacks-deploy
else echo "Note: couldn't add the sudo rule for /admin updates (visudo check failed); deploy over SSH as before."; fi
rm -f "$SUDOERS_TMP"

# CloudPanel's vhost serves css/js/images/fonts by file type straight from htdocs, not from the app
HTDOCS="${HTDOCS:-$HOME_DIR/htdocs/$DOMAIN}"
if [ -d "$HTDOCS" ]; then
  install -d -o "$SITE_USER" -g "$GROUP" "$HTDOCS/static"
  rsync -a --delete "$APP/static/" "$HTDOCS/static/"
  install -o "$SITE_USER" -g "$GROUP" -m 644 "$APP/static/favicon.ico" "$HTDOCS/favicon.ico"   # browsers ask for /favicon.ico
  chown -R "$SITE_USER:$GROUP" "$HTDOCS/static"
  echo "Copied static files to $HTDOCS/static"
else
  echo "Note: $HTDOCS not found; CSS and images won't load until static/ is copied there (set HTDOCS=... and rerun)."
fi

say "Check"
ok=""
for _ in $(seq 1 15); do
  if curl -fsS "http://127.0.0.1:$APP_PORT/healthz" >/dev/null 2>&1; then ok=1; break; fi
  sleep 1
done
if [ -n "$ok" ]; then echo "App is answering on 127.0.0.1:$APP_PORT."
else echo "App did not answer on port $APP_PORT. Look at: tail -50 $LOGS/gunicorn.log"; exit 1; fi

echo
echo "Done. Site: https://$DOMAIN"
echo "  HTTPS: in CloudPanel, Sites > $DOMAIN > SSL/TLS > New Let's Encrypt Certificate (once DNS points here)."
echo "  Admin: https://$DOMAIN/admin"
if [ -n "$NEW_ADMIN_PW" ]; then
  echo "  Admin password (also in $APP/.env as ADMIN_PASSWORD):"
  echo "      $NEW_ADMIN_PW"
fi
