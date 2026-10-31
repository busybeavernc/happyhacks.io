"""Sending sign-in codes: email over SMTP, text messages through Telnyx (same settings as zipzip).

  AUTH_DELIVERY=send (default) | log     log: don't send, write the message to the app log (setup and testing)
  SMTP_HOST, SMTP_PORT (465 = SSL, 587 = STARTTLS), SMTP_USER, SMTP_PASSWORD, MAIL_FROM
  (or Flask-Mail names: MAIL_SERVER, MAIL_PORT, MAIL_USERNAME, MAIL_PASSWORD, MAIL_USE_SSL, MAIL_FROM_EMAIL, MAIL_FROM_NAME, MAIL_REPLY_TO)
  TELNYX_API_KEY, and TELNYX_FROM and/or TELNYX_MESSAGING_PROFILE_ID

    python -m happyhacks.notify test <email or mobile>   send a test message with the current .env settings
"""
import json
import logging
import smtplib
import ssl
import urllib.error
import urllib.request
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

from . import settings

log = logging.getLogger('happyhacks.auth')
BRAND = 'Happy Hacks'


class SendError(Exception):
    pass


def _log_mode():
    return str(settings.get('AUTH_DELIVERY', 'send')).lower() == 'log'


def _mail():
    g = settings.get
    host = g('SMTP_HOST') or g('MAIL_SERVER')
    user = g('SMTP_USER') or g('MAIL_USERNAME')
    port = int(g('SMTP_PORT') or g('MAIL_PORT') or 465)
    use_ssl = str(g('MAIL_USE_SSL', '')).lower() in ('1', 'true', 'yes', 'on') if g('MAIL_USE_SSL') not in (None, '') else port == 465
    sender = g('MAIL_FROM')
    if not sender and (g('MAIL_FROM_EMAIL') or user):
        sender = formataddr((g('MAIL_FROM_NAME') or BRAND, g('MAIL_FROM_EMAIL') or user))
    elif sender and '<' not in sender:
        sender = formataddr((g('MAIL_FROM_NAME') or BRAND, sender))
    return {'host': host, 'port': port, 'ssl': use_ssl, 'user': user or (sender or '').split('<')[-1].strip('> '),
            'password': g('SMTP_PASSWORD') or g('MAIL_PASSWORD') or '', 'from': sender, 'reply_to': g('MAIL_REPLY_TO')}


def email_ready():
    m = _mail()
    return _log_mode() or bool(m['host'] and m['from'])


def sms_ready():
    return _log_mode() or bool(settings.get('TELNYX_API_KEY') and (settings.get('TELNYX_FROM') or settings.get('TELNYX_MESSAGING_PROFILE_ID')))


def send_email(to, subject, text, html=None, from_name=None):
    if _log_mode():
        log.warning('AUTH_DELIVERY=log, email not sent. To %s: %s\n%s', to, subject, text)
        return
    if not email_ready():
        raise SendError('Email sign-in is not set up on this server yet (SMTP settings).')
    m = _mail()
    msg = EmailMessage()
    sender = m['from']
    if from_name:   # e.g. "ZipZip via Happy Hacks": same address, the app's name in the inbox
        sender = formataddr((from_name, sender.split('<')[-1].strip('> ') if '<' in sender else sender))
    msg['From'], msg['To'], msg['Subject'] = sender, to, subject
    if m['reply_to']:
        msg['Reply-To'] = m['reply_to']
    msg['Message-ID'] = make_msgid(domain=m['from'].split('@')[-1].strip('> '))
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype='html')
    try:
        if m['ssl']:
            with smtplib.SMTP_SSL(m['host'], m['port'], context=ssl.create_default_context(), timeout=20) as srv:
                srv.login(m['user'], m['password'])
                srv.send_message(msg)
        else:
            with smtplib.SMTP(m['host'], m['port'], timeout=20) as srv:
                srv.starttls(context=ssl.create_default_context())
                srv.login(m['user'], m['password'])
                srv.send_message(msg)
    except smtplib.SMTPAuthenticationError as e:
        log.error('email to %s failed: the mail server refused the login (%s)', to, e)
        raise SendError('The email could not be sent right now. Try again shortly.')
    except (smtplib.SMTPException, OSError) as e:
        log.error('email to %s failed: %s', to, e)
        raise SendError('The email could not be sent right now. Try again shortly.')


def send_sms(to, text):
    if _log_mode():
        log.warning('AUTH_DELIVERY=log, text not sent. To %s: %s', to, text)
        return
    if not sms_ready():
        raise SendError('Text-message sign-in is not set up yet. Use your email address.')
    body = {'to': to, 'text': text}
    if settings.get('TELNYX_FROM'):
        body['from'] = settings.get('TELNYX_FROM')
    if settings.get('TELNYX_MESSAGING_PROFILE_ID'):
        body['messaging_profile_id'] = settings.get('TELNYX_MESSAGING_PROFILE_ID')
    req = urllib.request.Request('https://api.telnyx.com/v2/messages', data=json.dumps(body).encode(), method='POST', headers={
        'Authorization': f"Bearer {settings.get('TELNYX_API_KEY')}", 'Content-Type': 'application/json', 'Accept': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=20):
            pass
    except urllib.error.HTTPError as e:
        log.error('text to %s failed: HTTP %s %s', to, e.code, e.read()[:400])
        raise SendError('The text could not be sent to that number. Check it, or use your email address.')
    except (urllib.error.URLError, OSError) as e:
        log.error('text to %s failed: %s', to, e)
        raise SendError('The text could not be sent right now. Try again, or use your email address.')


def _h(s):
    return str(s or '').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')


HH_LOOK = {'header': '#493C55', 'header_ink': '#FAF7F2', 'stripe': '#B8A6CE', 'page': '#FAF7F2', 'card': '#FFFDF9', 'ink': '#493C55',
           'muted': '#6E6378', 'button': '#493C55', 'button_ink': '#FAF7F2', 'line': '#ECE5DA', 'tagline_ink': '#7A6696'}


def _look(theme):
    """Email colours: the app's (happyhacks/themes) when signing in on the way to it, else Happy Hacks'."""
    if not theme:
        return dict(HH_LOOK)
    c = theme['light']
    return {'header': c['button'], 'header_ink': c['button_ink'], 'stripe': c['accent'], 'page': c['page'], 'card': c['card'],
            'ink': c['ink'], 'muted': c['muted'], 'button': c['button'], 'button_ink': c['button_ink'], 'line': c['line'],
            'tagline_ink': c['link']}


def sign_in_message(channel, to, code, link, purpose, name=None, app_name=None, theme=None, base_url=None):
    """The code + link, in the app's look when the sign-in is on its way to an app (with "A product of Happy Hacks"
    underneath), else in Happy Hacks' own."""
    brand = theme['name'] if theme else BRAND
    via = f' to continue to {app_name}' if app_name and not theme else ''
    what = {'signup': f'Welcome to {brand}! Confirm your account{via}', 'login': f'Sign in to {brand}{via}',
            'add_email': 'Confirm this email address', 'add_phone': 'Confirm this number'}.get(purpose, f'Sign in to {brand}')
    if channel == 'sms':
        tail = ' (your Happy Hacks account)' if theme else ''
        send_sms(to, f'{brand} code: {code}\n{what}{tail}: {link}\nExpires in 10 minutes. If you didn\'t ask for this, ignore it.')
        return
    base = (base_url or link.split('/account/')[0]).rstrip('/')
    hh_icon = f'{base}/static/apple-touch-icon.png'
    icon = (theme or {}).get('email_icon') or (None if theme else hh_icon)
    tagline = (theme or {}).get('tagline') or ('' if theme else 'A little help. A happier day.')
    L = _look(theme)
    font = (f"'{theme['font_body']}'," if theme and theme.get('font_body') else 'Nunito,') + '-apple-system,Segoe UI,Roboto,sans-serif'
    head_font = (f"'{theme['font_heading']}'," if theme and theme.get('font_heading') else 'Fredoka,') + '-apple-system,Segoe UI,Roboto,sans-serif'
    hello = f'Hi {name.split()[0]},\n\n' if name else ''
    credit = f'\n{brand} is a product of {BRAND}.' if theme else ''
    text = (f'{hello}{what}.\n\nYour code: {code}\n\nOr open this link: {link}\n\n'
            f"The code and link expire in 10 minutes. If you didn't ask for this, you can ignore this email.\n\n"
            f"{brand}{' · ' + tagline if tagline else ''}{credit}\n")
    button = f'Open {brand}' if purpose in ('login', 'signup') else 'Confirm it'
    logo = (f'<img src="{_h(icon)}" width="30" height="30" alt="" style="vertical-align:middle;border-radius:7px;margin-right:8px">'
            if icon else '')
    footer = (f'<p style="font-family:{font};font-size:12px;color:{L["muted"]};text-align:center;margin:14px 0 0">A product of '
              f'<img src="{_h(hh_icon)}" width="16" height="16" alt="" style="vertical-align:-3px;border-radius:4px;margin:0 3px">'
              f'<b style="color:{L["ink"]}">{BRAND}</b></p>') if theme else ''
    html = f"""<div style="background:{L['page']};padding:24px 12px">
<div style="font-family:{font};max-width:460px;margin:0 auto;background:{L['card']};border-radius:14px;overflow:hidden;color:{L['ink']};border:1px solid {L['line']}">
<div style="background:{L['header']};padding:16px 24px;border-bottom:4px solid {L['stripe']}">{logo}<span style="vertical-align:middle;color:{L['header_ink']};font:700 20px {head_font}">{_h(brand)}</span></div>
<div style="padding:22px 24px 26px">
<p style="font-size:15px;margin:0 0 10px">{('Hi ' + _h(name.split()[0]) + ',') if name else ''}</p>
<p style="font-size:15px;margin:0">{_h(what)}. Your code:</p>
<p style="font-size:34px;font-weight:700;letter-spacing:6px;margin:14px 0;color:{L['ink']}">{code}</p>
<p style="margin:0 0 16px"><a href="{_h(link)}" style="display:inline-block;background:{L['button']};color:{L['button_ink']};text-decoration:none;padding:12px 22px;border-radius:{'10px' if theme else '999px'};font-weight:700">{_h(button)}</a></p>
<p style="font-size:13px;color:{L['muted']};margin:0">The code and link expire in 10 minutes. If you didn't ask for this, you can ignore this email.</p>
{f'<p style="font-size:14px;color:{L["tagline_ink"]};margin:18px 0 0">{_h(tagline)}</p>' if tagline else ''}</div></div>
{footer}</div>"""
    send_email(to, f'{brand} code: {code}', text, html, from_name=f'{brand} via {BRAND}' if theme else None)


def _main(argv):
    import sys
    if len(argv) < 2 or argv[0] != 'test':
        print(__doc__)
        return 2
    from .accounts import parse_contact
    channel, target = parse_contact(argv[1])
    try:
        if channel == 'email':
            send_email(target, f'{BRAND} test email', f'This is a test from {BRAND}. Sign-in codes will arrive like this.')
        else:
            send_sms(target, f'{BRAND} test text. Sign-in codes will arrive like this.')
    except SendError as e:
        print('FAILED:', e)
        return 1
    print(f'Sent to {target}.')
    return 0


if __name__ == '__main__':
    import os
    import sys
    try:
        from dotenv import load_dotenv
        load_dotenv(os.path.join(settings.ROOT, '.env'))
    except ImportError:
        pass
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    sys.exit(_main(sys.argv[1:]))
