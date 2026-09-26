# coding: utf-8
"""see — LAN/WiFi client monitor: Flask API + scanner + gateway traffic monitor."""
import base64
import ipaddress
import json
import os
import socket
import subprocess
import threading
import time
import urllib.request

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


# ---------- 截图测速：GLM 视觉 OCR ----------
_OCR_LIMITS = {}


def _zai_key():
    try:
        data = json.loads(open('/root/.openclaw/secrets.json', encoding='utf-8').read())
        return data.get('models', {}).get('providers', {}).get('zai', {}).get('apiKey')
    except Exception:
        return None


@app.after_request
def _snap_cors(resp):
    if request.path == '/api/snapshots/ocr' or request.path == '/downloads/see-version.json':
        resp.headers['Access-Control-Allow-Origin'] = '*'
    return resp


def _parse_bytes(txt):
    import re
    if not txt:
        return None
    m = re.search(r'([\d,\.]+)\s*(TB|GB|MB|KB|B|字节)?', str(txt), re.I)
    if not m:
        return None
    num, unit = m.group(1), (m.group(2) or 'B').upper()
    if unit == '字节':
        unit = 'B'
    if ',' in num and '.' in num:
        num = num.replace(',', '')
    elif ',' in num:
        num = num.replace(',', '')
    elif num.count('.') > 1:
        parts = num.split('.')
        if len(parts[-1]) <= 2:
            num = ''.join(parts[:-1]) + '.' + parts[-1]
        else:
            num = num.replace('.', '')
    try:
        v = float(num)
    except Exception:
        return None
    mul = {'B': 1, 'KB': 1024, 'MB': 1024 ** 2, 'GB': 1024 ** 3, 'TB': 1024 ** 4}.get(unit)
    if mul is None:
        return None
    return int(v * mul)


@app.post('/api/snapshots/ocr')
def api_snap_ocr():
    ip = request.remote_addr or '?'
    now = time.time()
    cnt, win = _OCR_LIMITS.get(ip, (0, now))
    if now - win > 3600:
        cnt, win = 0, now
    cnt += 1
    _OCR_LIMITS[ip] = (cnt, win)
    if cnt > 12:
        return jsonify(ok=False, error='请求太频繁，请一小时后再试'), 429
    key = _zai_key()
    if not key:
        return jsonify(ok=False, error='视觉模型密钥未配置'), 500
    f = request.files.get('image')
    if f is None:
        return jsonify(ok=False, error='缺少图片'), 400
    data = f.read()
    if len(data) < 100 or len(data) > 8 * 1024 * 1024:
        return jsonify(ok=False, error='图片无效或超过8MB'), 400
    mime = f.mimetype if (f.mimetype or '').startswith('image/') else 'image/jpeg'
    b64 = base64.b64encode(data).decode('ascii')
    prompt = ('从截图逐字照抄网络流量累计数值，返回纯JSON不要markdown不要换算：'
              '{"up_text": "上行/发送/上传的累计数值和单位原样照抄(如 1,014.44MB 或 123456789字节)；同一数值若有多种单位表示只抄精度最高的(优先MB/KB详值，其次GB)；没有则null", '
              '"down_text": "下行/接收/下载的累计数值和单位原样照抄，规则同上；没有则null", '
              '"time_text": "截图中可见的连接时长或时间文字，没有则null"}。'
              '只要累计流量值，忽略速率(如KB/s)、限速阈值、信号强度等无关数字。')
    payload = json.dumps({
        'model': 'glm-4.6v',
        'messages': [{'role': 'user', 'content': [
            {'type': 'image_url', 'image_url': {'url': 'data:%s;base64,%s' % (mime, b64)}},
            {'type': 'text', 'text': prompt},
        ]}],
        'temperature': 0.1, 'max_tokens': 2000,
    }).encode()
    req = urllib.request.Request(
        'https://api.z.ai/api/coding/paas/v4/chat/completions', data=payload, method='POST',
        headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + key})
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            out = json.loads(resp.read().decode('utf-8'))
        text = (out['choices'][0]['message']['content'] or '').strip()
    except Exception as e:
        return jsonify(ok=False, error='识别失败: %s' % e), 502
    t = text.strip('`').strip()
    if t[:4].lower() == 'json':
        t = t[4:].strip()
    try:
        parsed = json.loads(t)
    except Exception:
        parsed = {'up_bytes': None, 'down_bytes': None, 'time_text': text[:120]}
    up = _parse_bytes(parsed.get('up_text'))
    down = _parse_bytes(parsed.get('down_text'))
    return jsonify(ok=True, up=up, down=down,
                   up_text=parsed.get('up_text'), down_text=parsed.get('down_text'),
                   time_text=parsed.get('time_text'), raw=text[:300])
