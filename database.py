"""SQLite for local previews; PostgreSQL for free persistent cloud storage."""
from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3

POSTGRES = bool(os.environ.get('DATABASE_URL'))

class PostgresConnection:
    def __init__(self, connection):
        self.connection = connection

    def execute(self, sql, args=()):
        if sql == 'BEGIN IMMEDIATE':
            # Serialize setup and attendance transitions across concurrent requests.
            return self.connection.execute('SELECT pg_advisory_xact_lock(89173216)')
        if sql.startswith('INSERT OR REPLACE INTO settings'):
            sql = sql.replace('INSERT OR REPLACE', 'INSERT') + ' ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value'
        return self.connection.execute(sql.replace('?', '%s'), args)

    def executescript(self, sql):
        for statement in sql.split(';'):
            if statement.strip():
                self.execute(statement)

    def commit(self):
        self.connection.commit()

@contextmanager
def connect():
    if POSTGRES:
        import psycopg
        from psycopg.rows import dict_row
        # Secrets stay server-side. TLS protects the cloud database connection.
        with psycopg.connect(os.environ['DATABASE_URL'], row_factory=dict_row, sslmode='require', connect_timeout=15, prepare_threshold=None) as connection:
            connection.execute('SET search_path TO injaz')
            try:
                yield PostgresConnection(connection)
            except psycopg.IntegrityError as error:
                raise sqlite3.IntegrityError('Database constraint violation') from error
    else:
        path = os.environ.get('INJAZ_DB', str(Path(__file__).with_name('attendance.sqlite3')))
        connection = sqlite3.connect(path, timeout=15)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

def initialize():
    with connect() as db:
        if POSTGRES:
            db.execute('CREATE SCHEMA IF NOT EXISTS injaz')
            db.execute('REVOKE ALL ON SCHEMA injaz FROM PUBLIC')
            primary_key = 'BIGSERIAL PRIMARY KEY'
            number = 'DOUBLE PRECISION'
        else:
            db.execute('PRAGMA journal_mode=WAL')
            primary_key = 'INTEGER PRIMARY KEY'
            number = 'REAL'
        db.executescript(f'''
        CREATE TABLE IF NOT EXISTS users(id {primary_key}, code TEXT UNIQUE NOT NULL, name TEXT NOT NULL, department TEXT NOT NULL, password TEXT NOT NULL, admin INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires {number} NOT NULL);
        CREATE TABLE IF NOT EXISTS records(id {primary_key}, user_id INTEGER NOT NULL, kind TEXT NOT NULL, timestamp TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS records_user_last ON records(user_id,id);
        CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires);
        ''')
