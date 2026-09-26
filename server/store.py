# coding: utf-8
"""SQLite storage for see: devices, events, per-minute traffic rollups."""
import os
import sqlite3
import threading
import time

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'see.db')


class Store:
    def __init__(self):
        os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(DB_PATH, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute('PRAGMA journal_mode=WAL')
        self._init()

    def _init(self):
        with self._lock:
            self._db.executescript('''
            CREATE TABLE IF NOT EXISTS devices(
                mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT DEFAULT '', vendor TEXT DEFAULT '',
                first_seen INTEGER DEFAULT 0, last_seen INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS events(
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, type TEXT,
                ip TEXT, mac TEXT, hostname TEXT DEFAULT '');
            CREATE TABLE IF NOT EXISTS traffic_min(
                minute INTEGER, ip TEXT, up INTEGER DEFAULT 0, down INTEGER DEFAULT 0,
                PRIMARY KEY(minute, ip));
            ''')
            self._db.commit()

    # ---------- devices ----------
    def upsert_device(self, mac, ip, hostname=None, vendor=None, ts=None):
        ts = ts or int(time.time())
        with self._lock:
            row = self._db.execute('SELECT * FROM devices WHERE mac=?', (mac,)).fetchone()
            if row is None:
                self._db.execute(
                    'INSERT INTO devices(mac, ip, hostname, vendor, first_seen, last_seen) VALUES(?,?,?,?,?,?)',
                    (mac, ip, hostname or '', vendor or '', ts, ts))
            else:
                self._db.execute(
                    'UPDATE devices SET ip=?, last_seen=?, hostname=CASE WHEN ?<>'' THEN ? ELSE hostname END,'
                    ' vendor=CASE WHEN ?<>'' THEN ? ELSE vendor END WHERE mac=?',
                    (ip, ts, hostname or '', hostname or '', vendor or '', vendor or '', mac))
            self._db.commit()

    def all_devices(self):
        with self._lock:
            return [dict(r) for r in self._db.execute('SELECT * FROM devices ORDER BY last_seen DESC')]

    # ---------- events ----------
    def add_event(self, etype, ip, mac, hostname=''):
        with self._lock:
            self._db.execute('INSERT INTO events(ts, type, ip, mac, hostname) VALUES(?,?,?,?,?)',
                             (int(time.time()), etype, ip, mac, hostname or ''))
            self._db.commit()

    def recent_events(self, limit=60):
        with self._lock:
            return [dict(r) for r in self._db.execute(
                'SELECT * FROM events ORDER BY id DESC LIMIT ?', (int(limit),))]

    # ---------- traffic ----------
    def merge_minute(self, minute, rows):
        """rows: {ip: (up, down)} merged into rollup for the given minute."""
        with self._lock:
            for ip, (up, down) in rows.items():
                self._db.execute(
                    'INSERT INTO traffic_min(minute, ip, up, down) VALUES(?,?,?,?)'
                    ' ON CONFLICT(minute, ip) DO UPDATE SET up=up+?, down=down+?',
                    (minute, ip, int(up), int(down), int(up), int(down)))
            self._db.commit()

    def minute_series(self, ip, minutes=60):
        start = int(time.time() // 60) - minutes
        with self._lock:
            return [dict(r) for r in self._db.execute(
                'SELECT minute, up, down FROM traffic_min WHERE ip=? AND minute>=? ORDER BY minute',
                (ip, start))]

    def totals_for(self, ip, since_minute=None):
        cond = 'AND minute>=?' if since_minute else ''
        args = [ip] + ([since_minute] if since_minute else [])
        with self._lock:
            r = self._db.execute(
                f'SELECT COALESCE(SUM(up),0) u, COALESCE(SUM(down),0) d FROM traffic_min WHERE ip=? {cond}',
                args).fetchone()
            return {'up': r['u'], 'down': r['d']}

    def today_totals(self):
        import datetime
        start = int(datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp() // 60)
        with self._lock:
            rows = self._db.execute(
                'SELECT ip, SUM(up) u, SUM(down) d FROM traffic_min WHERE minute>=? GROUP BY ip', (start,)).fetchall()
        return {r['ip']: {'up': r['u'], 'down': r['d']} for r in rows}
