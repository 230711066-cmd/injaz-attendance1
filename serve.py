"""Production WSGI entrypoint for the existing attendance request handlers."""
from email.message import Message
from http import HTTPStatus
import io
import os
from waitress import serve
from server import Handler, initialize

class WSGIHandler(Handler):
    def __init__(self, environ):
        self.path = environ.get('PATH_INFO', '/')
        if environ.get('QUERY_STRING'):
            self.path += '?' + environ['QUERY_STRING']
        self.client_address = (environ.get('REMOTE_ADDR', ''), 0)
        self.headers = Message()
        for key, value in environ.items():
            if key.startswith('HTTP_'):
                self.headers[key[5:].replace('_', '-')] = value
        for key in ('CONTENT_LENGTH', 'CONTENT_TYPE'):
            if environ.get(key):
                self.headers[key.replace('_', '-')] = environ[key]
        self.rfile = environ['wsgi.input']
        self.wfile = io.BytesIO()
        self.response_headers = []
        self.status = 200

    def send_response(self, code, message=None):
        self.status = code

    def send_header(self, key, value):
        self.response_headers.append((key, str(value)))

    def end_headers(self):
        pass

def application(environ, start_response):
    handler = WSGIHandler(environ)
    method = environ['REQUEST_METHOD']
    if method == 'GET':
        handler.do_GET()
    elif method == 'POST':
        handler.do_POST()
    else:
        handler.send({'error': 'Method not allowed'}, 405)
    start_response(f'{handler.status} {HTTPStatus(handler.status).phrase}', handler.response_headers)
    return [handler.wfile.getvalue()]

if __name__ == '__main__':
    if os.environ.get('RENDER') and not os.environ.get('DATABASE_URL'):
        raise RuntimeError('DATABASE_URL is required on Render: local storage is temporary.')
    initialize()
    serve(application, host='0.0.0.0', port=int(os.environ.get('PORT', '8765')), threads=8, max_request_body_size=16384, expose_tracebacks=False)
