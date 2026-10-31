"""How a Happy Hacks sign-in page looks when an app sends people there: the app's own colours, fonts and logo, with
"A product of Happy Hacks" underneath, so signing in to ZipZip still looks like ZipZip.

One file per registered app in happyhacks/themes/<client id>.json (and its mark, an SVG, next to it). Themes are chosen
only for apps registered in .env (sso.client), never from anything a link says about colours or logos, so a look-alike
site can't dress the sign-in page up as someone else.

  {"name", "tagline", "mark": "<file>.svg", "fonts_url": "https://fonts.googleapis.com/...", "font_heading", "font_body",
   "light": {page, card, ink, muted, line, button, button_ink, accent, link, field}, "dark": {...same, optional}}
"""
import json
import os
import re
from functools import lru_cache

from . import sso

DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'themes')
COLORS = ('page', 'card', 'ink', 'muted', 'line', 'button', 'button_ink', 'accent', 'link', 'field')
HEX = re.compile(r'^#[0-9A-Fa-f]{6}$')
FONT = re.compile(r'^[A-Za-z0-9 ]{1,40}$')


def _colors(d):
    if not isinstance(d, dict):
        return None
    out = {k: d[k] for k in COLORS if isinstance(d.get(k), str) and HEX.match(d[k])}
    return out if len(out) == len(COLORS) else None


@lru_cache(maxsize=32)
def _load(cid):
    path = os.path.join(DIR, f'{cid}.json')
    try:
        with open(path, encoding='utf-8') as fh:
            t = json.load(fh)
    except (OSError, ValueError):
        return None
    light = _colors(t.get('light'))
    if not light:
        return None
    mark = None
    m = str(t.get('mark') or '')
    if re.fullmatch(r'[a-z0-9-]+\.svg', m):
        try:
            with open(os.path.join(DIR, m), encoding='utf-8') as fh:
                mark = fh.read().strip()
        except OSError:
            mark = None
    fonts_url = str(t.get('fonts_url') or '')
    return {
        'id': cid,
        'name': str(t.get('name') or cid)[:40],
        'tagline': str(t.get('tagline') or '')[:80],
        'mark_svg': mark if mark and mark.startswith('<svg') and '<script' not in mark.lower() else None,
        'fonts_url': fonts_url if fonts_url.startswith('https://fonts.googleapis.com/') and '"' not in fonts_url else None,
        'font_heading': t['font_heading'] if FONT.match(str(t.get('font_heading') or '')) else None,
        'font_body': t['font_body'] if FONT.match(str(t.get('font_body') or '')) else None,
        'light': light,
        'dark': _colors(t.get('dark')),
    }


def for_client(cid):
    """The theme for a registered app, else None (the Happy Hacks look)."""
    c = sso.client(cid)
    if not c or not re.fullmatch(r'[a-z][a-z0-9-]{1,38}', c['id']):
        return None
    t = _load(c['id'])
    if t:
        return {**t, 'app_url': _app_url(c)}
    return None


def _app_url(c):
    from urllib.parse import urlsplit
    p = urlsplit(c['redirect_uris'][0])
    return f'{p.scheme}://{p.netloc}/'
