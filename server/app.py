# coding: utf-8
"""see — LAN/WiFi client monitor: Flask API + scanner + gateway traffic monitor."""
import ipaddress
import json
import os
import socket
import subprocess
import threading
import time

from flask import Flask, jsonify, request, send_from_directory

import store as store_mod
from scanner import Scanner
from sniffer import TrafficMonitor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
START_TS = time.time()


def load_config():
    cfg = {}
    path = os.path.join(ROOT, 'see.json')
    if os.path.exists(path):
        cfg = json.load(open(path, encoding='utf-8'))
    cfg.setdefault('port', 5040)
    cfg.setdefault('scan_interval', 10)
    cfg.setdefault('offline_after', 30)
    cfg.setdefault('gateway', 'auto')
    return cfg


def sh(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, text=True).strip()
    except Exception:  # noqa: BLE001
        return ''


def detect_iface():
    out = sh("ip route show default | awk '{print $5}' | head -1")
    return out or 'eth0'


def iface_cidr(iface):
    out = sh(f"ip -o addr show dev {iface} | awk '$3==\"inet\" {{print $4}}' | head -1")
    if out:
        return out  # e.g. 10.7.0.3/22
    # Termux 等无 iproute2 环境：UDP 探测本机出口 IP，按 /24 猜测
    try:
        sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sk.connect(('8.8.8.8', 80))
        ip = sk.getsockname()[0]
        sk.close()
        return ip + '/24'
    except Exception:  # noqa: BLE001
        return 


cfg = load_config()
IFACE = cfg.get('iface') or detect_iface()
CIDR = iface_cidr(IFACE)
OWN_IP = CIDR.split('/')[0] if '/' in CIDR else ''
SUBNET = str(ipaddress.ip_network(CIDR, strict=False)) if '/' in CIDR else ''

ip_forward = False
try:
    ip_forward = open('/proc/sys/net/ipv4/ip_forward').read().strip() == '1'
except Exception:
    pass
gw_cfg = cfg.get('gateway')
GATEWAY = bool(ip_forward) if gw_cfg == 'auto' else (gw_cfg is True)

store = store_mod.Store()
scanner = Scanner(store, SUBNET, IFACE, interval=cfg['scan_interval'], offline_after=cfg['offline_after'], scan_mode=cfg.get('scan_mode', 'auto'))
scanner.prime_known()
_EXTRA_IPS = {OWN_IP} if OWN_IP else set()
local_ips = lambda: scanner.local_ips() | _EXTRA_IPS  # noqa: E731
monitor = TrafficMonitor(IFACE, local_ips, enabled=GATEWAY)

app = Flask(__name__, static_folder=os.path.join(ROOT, 'static'), static_url_path='')
_last_rolled = {}


def start_background():
    scanner.start()
    monitor.start()
    threading.Thread(target=_tick_loop, daemon=True).start()
    if GATEWAY:
        threading.Thread(target=_rollup_loop, daemon=True).start()


def _tick_loop():
    while True:
        time.sleep(2)
        try:
            monitor.tick()
        except Exception:  # noqa: BLE001
            pass


def _rollup_loop():
    while True:
        time.sleep(60)
        try:
            minute = int(time.time()) // 60 - 1
            rows = {}
            with monitor.lock:
                for ip in set(monitor.up) | set(monitor.down):
                    u, d = monitor.up.get(ip, 0), monitor.down.get(ip, 0)
                    lu, ld = _last_rolled.get(ip, (0, 0))
                    if u - lu > 0 or d - ld > 0:
                        rows[ip] = (u - lu, d - ld)
                    _last_rolled[ip] = (u, d)
            if rows:
                store.merge_minute(minute, rows)
        except Exception:  # noqa: BLE001
            pass


def _live_today(ip):
    """today total = DB rollups + un-rolled live delta."""
    base = store.totals_for(ip)
    with monitor.lock:
        u, d = monitor.up.get(ip, 0), monitor.down.get(ip, 0)
    lu, ld = _last_rolled.get(ip, (0, 0))
    return {'up': base['up'] + max(u - lu, 0), 'down': base['down'] + max(d - ld, 0)}


# ---------- pages ----------
@app.route('/')
def index():
    return send_from_directory(os.path.join(ROOT, 'static'), 'index.html')


# ---------- api ----------
@app.get('/api/status')
def api_status():
    devs = scanner.devices()
    online = sum(1 for d in devs if d['online'])
    tot_sp = {'up': 0, 'down': 0}
    if GATEWAY:
        for d in devs:
            sp = monitor.speeds(d['ip'])
            tot_sp['up'] += sp['up']
            tot_sp['down'] += sp['down']
    return jsonify(ok=True, mode='gateway' if GATEWAY else 'observer', iface=IFACE,
                   subnet=SUBNET, ip=OWN_IP, uptime=int(time.time() - START_TS),
                   online=online, devices=len(devs), total_speed=tot_sp,
                   pkt_count=monitor.pkt_count, scan_error=scanner.last_error,
                   last_sweep=scanner.last_sweep)


@app.get('/api/devices')
def api_devices():
    out = []
    for d in scanner.devices():
        ip = d['ip']
        sp = monitor.speeds(ip) if GATEWAY else {'up': 0, 'down': 0}
        sess = monitor.totals(ip) if GATEWAY else {'up': 0, 'down': 0}
        out.append({'mac': d['mac'], 'ip': ip, 'hostname': d['hostname'], 'vendor': d['vendor'],
                    'online': d['online'], 'last_seen': d['last_seen'], 'speed': sp,
                    'session': sess, 'today': _live_today(ip) if GATEWAY else {'up': 0, 'down': 0}})
    out.sort(key=lambda x: (not x['online'], -(x['speed']['up'] + x['speed']['down'])))
    return jsonify(ok=True, devices=out)


@app.get('/api/events')
def api_events():
    limit = request.args.get('limit', 60, type=int)
    return jsonify(ok=True, events=store.recent_events(min(limit, 300)))


@app.get('/api/device')
def api_device():
    ip = (request.args.get('ip') or '').strip()
    if not ip:
        return jsonify(ok=False, error='missing ip'), 400
    dev = None
    for d in scanner.devices():
        if d['ip'] == ip:
            dev = d
            break
    if dev is None:
        dev = {'ip': ip, 'mac': '', 'hostname': '', 'vendor': '', 'online': False, 'last_seen': 0}
    series = store.minute_series(ip, 90)
    return jsonify(ok=True, device=dev, series=series,
                   apps=monitor.apps(ip) if GATEWAY else [],
                   today=_live_today(ip) if GATEWAY else {'up': 0, 'down': 0},
                   session=monitor.totals(ip) if GATEWAY else {'up': 0, 'down': 0})
