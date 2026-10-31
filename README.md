# happyhacks.io

Parent site for HappyHacks products (ZipZip, Doppleganger, …). Flask app served by gunicorn on **127.0.0.1:9010** under supervisor, behind CloudPanel's nginx — same layout as ZipZip.

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

- **Sign-in:** `ADMIN_PASSWORD` in `.env`. `install.sh` generates one the first time and prints it. To change it, edit `.env` and run `sudo supervisorctl restart happyhacks`. Five wrong tries lock that IP out for 15 minutes.
- **Update live site** runs `sudo -n /usr/local/sbin/happyhacks-deploy` in its own session, so it survives the app restarting mid-deploy. `install.sh` writes `/etc/sudoers.d/happyhacks-deploy`, which allows the site user to run that one command as root and nothing else.
- Update logs: `~/logs/happyhacks-updates/` (site user's home).
