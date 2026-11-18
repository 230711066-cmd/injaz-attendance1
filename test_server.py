import http.cookiejar
import importlib.metadata
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

class ServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            cls.port = sock.getsockname()[1]
        env = dict(os.environ, INJAZ_DB=str(Path(cls.temp.name)/'test.sqlite3'), PORT=str(cls.port))
        env.pop('DATABASE_URL', None)
        env.pop('INJAZ_HTTPS', None)
        entry = getattr(cls, 'entry', 'server.py')
        args = ['--host', '127.0.0.1', '--port', str(cls.port)] if entry == 'server.py' else []
        cls.process = subprocess.Popen([sys.executable, str(Path(__file__).with_name(entry)), *args], env=env, stdout=subprocess.DEVNULL)
        cls.base = f'http://127.0.0.1:{cls.port}'
        cls.admin = cls.client()
        cls.employee = cls.client()
        cls.other = cls.client()
        for _ in range(80):
            try:
                cls.request(cls.admin, 'me')
                break
            except urllib.error.URLError:
                time.sleep(.1)
        else:
            raise RuntimeError('Server did not start')

    @staticmethod
    def client():
        return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    @classmethod
    def request(cls, client, path, body=None, header=True):
        headers = {'Content-Type': 'application/json'}
        if header:
            headers['X-Injaz'] = '1'
        request = urllib.request.Request(cls.base+'/api/'+path, data=json.dumps(body).encode() if body is not None else None, headers=headers)
        try:
            response = client.open(request)
        except urllib.error.HTTPError as error:
            response = error
        data = response.read()
        return response.status, json.loads(data) if 'json' in response.headers.get('Content-Type', '') else data

    def test_shared_attendance(self):
        a, e, o = self.admin, self.employee, self.other
        self.assertEqual(self.request(a,'setup',{'code':'ADMIN','password':'Strong-admin-123'})[0],200)
        self.assertEqual(self.request(o,'setup',{'code':'OTHER','password':'Strong-admin-123'})[0],409)
        self.assertEqual(self.request(o,'records')[0],403)
        self.assertEqual(self.request(o,'login',{'code':'MISSING','password':'dummy'})[0],401)
        for code, name in [('E1','موظف أول'),('E2','موظف ثان')]:
            self.assertEqual(self.request(a,'users',{'code':code,'name':name,'department':'صيانة','password':'Staff-secret-123'})[0],200)
        self.assertEqual(self.request(a,'users',{'code':'E1','name':'مكرر','department':'صيانة','password':'Staff-secret-123'})[0],409)
        self.assertEqual(self.request(e,'login',{'code':'E1','password':'wrong'})[0],401)
        self.assertEqual(self.request(e,'login',{'code':'E1','password':'Staff-secret-123'})[0],200)
        self.assertEqual(self.request(o,'login',{'code':'E2','password':'Staff-secret-123'})[0],200)
        self.assertEqual(self.request(e,'users')[0],403)
        self.assertEqual(self.request(e,'settings',{'url':'http://example.com'})[0],403)
        self.assertEqual(self.request(e,'attendance',{'kind':'in'},header=False)[0],403)
        self.assertEqual(self.request(e,'attendance',{'kind':'out'})[0],409)
        self.assertEqual(self.request(e,'attendance',{'kind':'in'})[0],200)
        self.assertEqual(self.request(e,'attendance',{'kind':'in'})[0],409)
        self.assertEqual(len(self.request(o,'records')[1]),0)
        self.assertEqual(self.request(e,'attendance',{'kind':'out'})[0],200)
        self.assertEqual(len(self.request(a,'records')[1]),2)
        self.assertEqual(self.request(a,'settings',{'url':'javascript:alert(1)'})[0],400)
        self.assertEqual(self.request(a,'settings',{'url':'http://192.168.1.20:8765'})[0],200)
        status, svg = self.request(a,'qr')
        self.assertEqual(status,200)
        self.assertIn(b'<svg',svg)
        users = self.request(a,'users')[1]
        self.assertTrue(all('password' not in u for u in users))
        uid = next(u['id'] for u in users if u['code']=='E1')
        self.assertEqual(self.request(a,'password',{'id':uid,'password':'New-password-123'})[0],200)
        self.assertEqual(self.request(e,'records')[0],403)
        self.assertEqual(self.request(e,'login',{'code':'E1','password':'New-password-123'})[0],200)
        self.assertEqual(len(self.request(e,'records')[1]),2)
        self.assertEqual(self.request(e,'logout',{})[0],200)
        self.assertEqual(self.request(e,'records')[0],403)

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        cls.process.wait(timeout=10)
        cls.temp.cleanup()

class WSGITest(ServerTest):
    entry = 'serve.py'

if __name__ == '__main__':
    unittest.main()
