# happyhacks.io

Parent site for HappyHacks products (ZipZip, BRB, …). Flask app served by gunicorn on **127.0.0.1:9010** under supervisor, behind CloudPanel's nginx — same layout as ZipZip.

## Layout

```
happyhacks/            Flask package (app factory, templates)
  products.py          Product catalog — add new products here
static/                CSS/images (install.sh copies these into htdocs/happyhacks.io/static)
wsgi.py                WSGI entry point (wsgi:app), loads .env
.env.example           Settings template (APP_PORT=9010, SECRET_KEY)
deploy/
  gunicorn.conf.py     Binds 127.0.0.1:$APP_PORT
  cloudpanel/
    install.sh         Install/update on the server (venv, .env, supervisor, static copy, health check)
    deploy.sh          Installed as `sudo happyhacks-deploy`: deploy key + git pull + install.sh
    supervisor.conf.template
tests/                 unittest smoke tests (run by install.sh)
```

## Local dev

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python wsgi.py                       # http://localhost:5000
python -m unittest discover -s tests
```

## First-time server setup (CloudPanel)

1. CloudPanel: **Add Site > Python**, domain `happyhacks.io`, App Port **9010**, and paste the vhost. Note the site user.
2. As the site user, clone outside htdocs:
   ```bash
   git clone https://github.com/busybeavernc/happyhacks.io.git ~/happyhacks
   ```
   (Private repo? Run step 3 first via `sudo APP=/home/<site user>/happyhacks happyhacks-deploy` after copying, or make the clone with a deploy key — `happyhacks-deploy` prints the key to add on GitHub.)
3. As root:
   ```bash
   sudo SITE_USER=<site user> bash /home/<site user>/happyhacks/deploy/cloudpanel/install.sh
   ```
4. CloudPanel: **SSL/TLS > New Let's Encrypt Certificate** (happyhacks.io + www).

## Deploying updates

```bash
sudo happyhacks-deploy
```

The first run creates a deploy key (`~/.ssh/happyhacks_deploy`) and prints it; add it at GitHub > repo > Settings > Deploy keys (read-only), then run again. It uses its own SSH host alias, so it won't clash with ZipZip's deploy key.

## Admin (/admin)

`https://happyhacks.io/admin` lets you run the deploy from the browser and watch its output, like ZipZip's dashboard.

- **Hidden:** every `/admin` address answers 404 until an administrator unlocks it. Set up their authenticator on the
  server with `python -m happyhacks.accounts totp you@example.com` (`totp-off` removes it). Then, signed in, on
  `/account` type the unlock word (`ADMIN_UNLOCK_KEYS`, default `unlock`) within 10 seconds of the page loading, or tap
  the "Hi, ..." heading 5 times, and enter the 6-digit code. Admin stays open in that browser for 30 minutes after the
  last use (12 hours at most). Unlocks, blocked unlocks, recovery sign-ins, a new network address, website updates and
  administrator/authenticator changes are emailed to `ADMIN_ALERT_EMAIL` and the administrator.
- **Who:** a Happy Hacks account with the **admin** role. Make an account an administrator, once it exists:
  `python -m happyhacks.accounts admin you@example.com` (or `unadmin`; `list` shows roles), or put the address in
  `ADMIN_CONTACTS=` in `.env` and it becomes one at its next sign-in. The role is **Happy Hacks only**: it is never sent
  to ZipZip or other apps, and their roles never come in.
- **Recovery:** `ADMIN_PASSWORD` in `.env` works on `/admin/login` only while `ADMIN_RECOVERY=1` is also set (e.g.
  if email sign-in is down). Switch it on, get in, switch it off. Every use is emailed.
- **Update live site** runs `sudo -n /usr/local/sbin/happyhacks-deploy` in its own session, so it survives the app restarting mid-deploy. `install.sh` writes `/etc/sudoers.d/happyhacks-deploy`, which allows the site user to run that one command as root and nothing else.
- Update logs: `~/logs/happyhacks-updates/` (site user's home).

## App branding on the sign-in pages

When an app sends someone to sign in ("Sign in with Happy Hacks"), the sign-in, code and link pages wear **that app's**
look: its logo, name, tagline, colours, fonts and dark mode, with "A product of Happy Hacks" and the Smiling H under the
panel. Signing in from happyhacks.io itself keeps the Happy Hacks look.

Each registered app gets a file in `happyhacks/themes/`: `<client id>.json` (name, tagline, mark, Google Fonts URL, font
names, `light` and optional `dark` colours) and its mark as an SVG (colours as `var(--t-ink)`, `var(--t-accent)`,
`var(--t-card)` so it follows light/dark). See `zipzip.json`. A theme is used only for an app registered in `.env`
(`HH_CLIENTS`), never from anything in a link, so another site can't make the sign-in page look like someone else's.

## Automatik phone link (/automatik/)

A chat app (PWA) for the owner's Automatik PC, plus a **blind relay**: requests from the phone are encrypted to the PC
and signed with the phone's passkey, so this site only stores ciphertext for a few minutes. The PC collects them by
polling `/automatik/relay/*` with `AUTOMATIK_RELAY_KEY`. There is no route here that adds or removes devices: that is
done only on the PC (`python -m remote enroll`). Settings: the `AUTOMATIK_*` lines in `.env.example`; code:
`happyhacks/automatik.py`, `happyhacks/templates/automatik/`, `static/automatik/`; tests `tests/test_automatik.py`.
