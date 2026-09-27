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
            CREATE TABLE IF NOT EXISTS gw_samples(
                ts INTEGER, devkey TEXT, name TEXT DEFAULT '', ip TEXT DEFAULT '',
                present INTEGER DEFAULT 0, up REAL DEFAULT 0, down REAL DEFAULT 0);
            CREATE INDEX IF NOT EXISTS idx_gws_key_ts ON gw_samples(devkey, ts);
            CREATE INDEX IF NOT EXISTS idx_gws_ts ON gw_samples(ts);
            ''')
            # link（有线/无线）：老库没有这列，补上（采集器新版才会填；空值=未知）
            cols = [r[1] for r in self._db.execute('PRAGMA table_info(gw_samples)')]
            if 'link' not in cols:
                self._db.execute("ALTER TABLE gw_samples ADD COLUMN link TEXT DEFAULT ''")
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
                sets = ['ip=?', 'last_seen=?']
                vals = [ip, ts]
                if hostname:
                    sets.append('hostname=?')
                    vals.append(hostname)
                if vendor:
                    sets.append('vendor=?')
                    vals.append(vendor)
                vals.append(mac)
                self._db.execute(
                    'UPDATE devices SET ' + ', '.join(sets) + ' WHERE mac=?', vals)
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

    # ---------- 网关设备流量采样（app 上传）----------
    def add_gw_samples(self, rows):
        """rows: iterable of (ts, devkey, name, ip, present, up, down[, link])  —— 第 8 项可选"""
        vals = []
        for r in rows:
            try:
                ts = int(r[0]); key = str(r[1])[:64]
                name = str(r[2] or '')[:64]; ip = str(r[3] or '')[:64]
                present = 1 if r[4] else 0
                up = float(r[5] or 0); down = float(r[6] or 0)
                link = str(r[7] or '')[:16] if len(r) > 7 else ''
            except Exception:  # noqa: BLE001
                continue
            if not key or ts <= 0:
                continue
            vals.append((ts, key, name, ip, present, up, down, link))
        if not vals:
            return 0
        with self._lock:
            self._db.executemany(
                'INSERT OR IGNORE INTO gw_samples(ts, devkey, name, ip, present, up, down, link)'
                ' VALUES(?,?,?,?,?,?,?,?)', vals)
            self._db.commit()
        return len(vals)

    def gw_latest(self, since, window=900):
        """每台设备最近一条采样，外加以「present 连续段」推算的在线时长。

        since: 只返回最近一条 ts 不早于它的设备（太久没数据=已经不在网里）。
        window: 连续在线允许的最大采样间隔（秒）；断档超过它就从那段重新计时。
        """
        now = int(time.time())
        out = []
        with self._lock:
            rows = self._db.execute(
                'SELECT s.devkey, s.ts, s.name, s.ip, s.present, s.up, s.down, s.link'
                '  FROM gw_samples s'
                '  JOIN (SELECT devkey, MAX(ts) mts FROM gw_samples GROUP BY devkey) m'
                '    ON s.devkey=m.devkey AND s.ts=m.mts'
                ' WHERE s.ts>=?', (int(since),)).fetchall()
            for r in rows:
                online = 0
                if r['present']:
                    start = r['ts']; prev = now
                    for p in self._db.execute(
                            'SELECT ts, present FROM gw_samples WHERE devkey=? AND ts<=?'
                            ' ORDER BY ts DESC LIMIT 500', (r['devkey'], now)):
                        if not p['present']:
                            break
                        if prev - p['ts'] > window:
                            break
                        start = p['ts']; prev = p['ts']
                    online = max(0, now - start)
                out.append({
                    'key': r['devkey'], 'name': r['name'] or '', 'ip': r['ip'] or '',
                    'link': r['link'] or '', 'present': 1 if r['present'] else 0,
                    'up': float(r['up'] or 0), 'down': float(r['down'] or 0),
                    'ts': int(r['ts']), 'online_time': online,
                })
        out.sort(key=lambda d: -((d['up'] or 0) + (d['down'] or 0)))
        return out

    def gw_keys(self, since):
        with self._lock:
            return [dict(r) for r in self._db.execute(
                'SELECT devkey AS key, MAX(name) name, MAX(ip) ip, MAX(ts) last_ts'
                ' FROM gw_samples WHERE ts>=? GROUP BY devkey ORDER BY last_ts DESC', (int(since),))]

    def gw_series(self, devkey, frm, to):
        with self._lock:
            return [dict(r) for r in self._db.execute(
                'SELECT ts, present, up, down FROM gw_samples WHERE devkey=? AND ts>=? AND ts<? ORDER BY ts',
                (devkey, int(frm), int(to)))]

    def gw_last_link(self):
        """devkey -> 最近一次已知的链路类型（有线/无线），给没带 link 的采样兜底"""
        with self._lock:
            rows = self._db.execute(
                "SELECT devkey, link FROM gw_samples WHERE link<>''"
                ' GROUP BY devkey HAVING ts=MAX(ts)').fetchall()
        return {r['devkey']: r['link'] for r in rows}

    def prune_gw_samples(self, before):
        with self._lock:
            self._db.execute('DELETE FROM gw_samples WHERE ts<?', (int(before),))
            self._db.commit()
