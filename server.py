"""INJAZ shared attendance server. Run: python server.py"""
import argparse
import csv
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import time
from datetime import datetime, timezone, timedelta
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from database import connect, initialize

ROOT = Path(__file__).resolve().parent
DB = Path(os.environ.get('INJAZ_DB', str(ROOT / 'attendance.sqlite3')))
TZ = timezone(timedelta(hours=3))
FAILURES = {}

def password_hash(value, salt=None):
    salt = salt or secrets.token_hex(16)
    return salt + ':' + hashlib.pbkdf2_hmac('sha256', value.encode(), salt.encode(), 300000).hex()

def public_user(row):
    return {k: row[k] for k in ('id', 'code', 'name', 'department', 'admin')}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def send(self, data, status=200, mime='application/json; charset=utf-8', cookie=None):
        if getattr(self, '_defer_response', False):
            self._pending_response = (data, status, mime, cookie)
            return
        payload = json.dumps(data, ensure_ascii=False).encode() if mime.startswith('application/json') else data
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'same-origin')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(payload)

    def user(self, db):
        try:
            cookies = SimpleCookie(self.headers.get('Cookie', ''))
            token = cookies['injaz_session'].value
        except (KeyError, ValueError):
            return None
        return db.execute('SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.token=? AND s.expires>?', (hashlib.sha256(token.encode()).hexdigest(), time.time())).fetchone()

    def require(self, db, admin=False):
        user = self.user(db)
        if user is None or (admin and not user['admin']):
            self.send({'error': 'سجل الدخول بحساب الإدارة.' if admin else 'سجل الدخول أولاً.'}, 403)
            return None
        return user

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == '/api/health':
            return self.send({'ok': True})
        if path in ('/', '/attendance'):
            return self.send((ROOT / 'portal.html').read_bytes(), mime='text/html; charset=utf-8')
        with connect() as db:
            if path == '/api/me':
                user = self.user(db)
                return self.send({'user': public_user(user) if user else None, 'setup': not bool(db.execute('SELECT 1 FROM users LIMIT 1').fetchone()), 'local': self.client_address[0] in ('127.0.0.1', '::1') and os.environ.get('INJAZ_HTTPS') != '1', 'setupTokenRequired': os.environ.get('INJAZ_HTTPS') == '1' or self.client_address[0] not in ('127.0.0.1', '::1')})
            user = self.require(db)
            if not user:
                return
            if path == '/api/records':
                query = 'SELECT r.*,u.name,u.code,u.department FROM records r JOIN users u ON u.id=r.user_id'
                args = ()
                if not user['admin']:
                    query += ' WHERE r.user_id=?'
                    args = (user['id'],)
                return self.send([dict(r) for r in db.execute(query + ' ORDER BY r.id DESC', args)])
            if not user['admin']:
                return self.send({'error': 'هذه الصفحة للإدارة فقط.'}, 403)
            if path == '/api/users':
                return self.send([public_user(r) for r in db.execute('SELECT * FROM users ORDER BY id')])
            if path == '/api/settings':
                row = db.execute("SELECT value FROM settings WHERE key='url'").fetchone()
                return self.send({'url': row['value'] if row else ''})
            if path == '/api/qr':
                row = db.execute("SELECT value FROM settings WHERE key='url'").fetchone()
                if not row:
                    return self.send({'error': 'احفظ رابط النظام أولاً.'}, 400)
                import qrcode
                import qrcode.image.svg
                qr = qrcode.make(row['value'] + '/attendance', image_factory=qrcode.image.svg.SvgPathImage, border=4)
                stream = io.BytesIO()
                qr.save(stream)
                return self.send(stream.getvalue(), mime='image/svg+xml')
        return self.send({'error': 'الصفحة غير موجودة.'}, 404)

    def do_POST(self):
        if self.headers.get('X-Injaz') != '1' or self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
            return self.send({'error': 'طلب غير مسموح.'}, 403)
        # Acknowledge writes only after the database transaction has committed.
        self._defer_response = True
        self._pending_response = None
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 16384:
                raise ValueError()
            body = json.loads(self.rfile.read(size))
            if not isinstance(body, dict):
                raise ValueError()
            self.post(urlsplit(self.path).path, body)
        except (ValueError, TypeError, KeyError):
            self.send({'error': 'راجع البيانات المدخلة.'}, 400)
        except sqlite3.IntegrityError:
            self.send({'error': 'رقم الموظف مستخدم مسبقاً.'}, 409)
        except Exception:
            self.send({'error': 'تعذر حفظ العملية. حاول مرة أخرى أو راجع الإدارة.'}, 503)
        finally:
            self._defer_response = False
            if self._pending_response:
                self.send(*self._pending_response)

    def post(self, path, body):
        with connect() as db:
            if path in ('/api/setup', '/api/login'):
                code = str(body.get('code', '')).strip().upper()
                password = str(body.get('password', ''))
                if path == '/api/setup':
                    remote_setup = self.client_address[0] not in ('127.0.0.1', '::1') or os.environ.get('INJAZ_HTTPS') == '1'
                    expected_token = os.environ.get('INJAZ_SETUP_TOKEN', '')
                    if remote_setup and (not expected_token or not hmac.compare_digest(expected_token, str(body.get('setupToken', '')))):
                        return self.send({'error': 'أدخل رمز إعداد الإدارة المحدد في إعدادات الاستضافة.'}, 403)
                    db.execute('BEGIN IMMEDIATE')
                    if db.execute('SELECT 1 FROM users LIMIT 1').fetchone():
                        return self.send({'error': 'تم إعداد الإدارة مسبقاً.'}, 409)
                    if not code or len(code) > 40 or len(password) < 10 or len(password) > 200:
                        return self.send({'error': 'أدخل رقماً وكلمة مرور من 10 أحرف على الأقل.'}, 400)
                    db.execute('INSERT INTO users(code,name,department,password,admin) VALUES(?,?,?,?,1)', (code, 'مدير النظام', 'الإدارة', password_hash(password)))
                    db.commit()
                ip = self.client_address[0]
                failures = [t for t in FAILURES.get(ip, []) if t > time.time()-300]
                if len(failures) >= 10:
                    return self.send({'error': 'محاولات كثيرة. انتظر خمس دقائق.'}, 429)
                user = db.execute('SELECT * FROM users WHERE code=?', (code,)).fetchone()
                stored = user['password'] if user else password_hash('dummy')
                matched = hmac.compare_digest(stored, password_hash(password[:200], stored.split(':')[0]))
                if not user or not matched or len(password) > 200:
                    FAILURES[ip] = failures + [time.time()]
                    return self.send({'error': 'رقم الموظف أو كلمة المرور غير صحيحة.'}, 401)
                FAILURES.pop(ip, None)
                token = secrets.token_urlsafe(32)
                db.execute('DELETE FROM sessions WHERE expires<?', (time.time(),))
                db.execute('INSERT INTO sessions VALUES(?,?,?)', (hashlib.sha256(token.encode()).hexdigest(), user['id'], time.time()+43200))
                secure = '; Secure' if os.environ.get('INJAZ_HTTPS') == '1' else ''
                return self.send({'user': public_user(user)}, cookie=f'injaz_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200{secure}')
            user = self.require(db)
            if not user:
                return
            if path == '/api/logout':
                db.execute('DELETE FROM sessions WHERE user_id=?', (user['id'],))
                return self.send({'ok': True}, cookie='injaz_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')
            if path == '/api/attendance':
                kind = body.get('kind')
                if kind not in ('in', 'out'):
                    raise ValueError()
                db.execute('BEGIN IMMEDIATE')
                last = db.execute('SELECT kind FROM records WHERE user_id=? ORDER BY id DESC LIMIT 1', (user['id'],)).fetchone()
                if (last and last['kind'] == kind) or (not last and kind == 'out'):
                    return self.send({'error': 'الحركة مسجلة مسبقاً؛ اختر الحركة التالية.' if last else 'سجل حضورك أولاً.'}, 409)
                db.execute('INSERT INTO records(user_id,kind,timestamp) VALUES(?,?,?)', (user['id'], kind, datetime.now(TZ).isoformat(timespec='seconds')))
                return self.send({'ok': True})
            if not user['admin']:
                return self.send({'error': 'هذه العملية للإدارة فقط.'}, 403)
            if path == '/api/users':
                values = [str(body.get(k, '')).strip() for k in ('code', 'name', 'department', 'password')]
                if any(not v or len(v) > 200 for v in values) or len(values[3]) < 10 or len(values[0]) > 40:
                    return self.send({'error': 'أكمل البيانات وكلمة مرور من 10 أحرف على الأقل.'}, 400)
                values[0] = values[0].upper()
                values[3] = password_hash(values[3])
                db.execute('INSERT INTO users(code,name,department,password) VALUES(?,?,?,?)', values)
                return self.send({'ok': True})
            if path == '/api/settings':
                url = str(body.get('url', '')).rstrip('/')
                parts = urlsplit(url)
                if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password or parts.path or parts.query or parts.fragment or len(url)>500:
                    return self.send({'error': 'أدخل رابطاً مثل http://192.168.1.20:8765 بدون مسار إضافي.'}, 400)
                db.execute("INSERT OR REPLACE INTO settings VALUES('url',?)", (url,))
                return self.send({'ok': True})
            if path == '/api/password':
                password = str(body.get('password', ''))
                target = int(body.get('id', 0))
                if not 10 <= len(password) <= 200:
                    raise ValueError()
                db.execute('UPDATE users SET password=? WHERE id=?', (password_hash(password), target))
                db.execute('DELETE FROM sessions WHERE user_id=?', (target,))
                return self.send({'ok': True})
        self.send({'error': 'العملية غير موجودة.'}, 404)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=int(os.environ.get('PORT', '8765')))
    args = parser.parse_args()
    initialize()
    print(f'INJAZ: http://localhost:{args.port}', flush=True)
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()

if __name__ == '__main__':
    main()
