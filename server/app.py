# coding: utf-8
"""see — LAN/WiFi client monitor: Flask API + scanner + gateway traffic monitor."""
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
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
_LAST_PRUNE = [0.0]


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


# 允许携带凭据的来源：公网页 + 手机 app 内置页面(127.0.0.1:5050)。
# 之前是 Access-Control-Allow-Origin: *，等于谁都能从任意站点带着密钥调接口。
ALLOW_ORIGINS = {'https://5130599.best', 'http://127.0.0.1:5050', 'http://localhost:5050'}


def _origin_ok(org):
    if not org:
        return False
    if org in ALLOW_ORIGINS:
        return True
    # 手机上用局域网 IP 打开内置页面时也要能用
    return bool(re.fullmatch(r'http://(127\.0\.0\.1|localhost|(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))[\d\.]*):5050', org))


@app.after_request
def _cors(resp):
    if request.path.startswith('/api/'):
        org = request.headers.get('Origin') or ''
        if _origin_ok(org):
            resp.headers['Access-Control-Allow-Origin'] = org
            resp.headers['Vary'] = 'Origin'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-See-Key, X-See-Session'
        resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        resp.headers['Cache-Control'] = 'no-store'
    elif request.path == '/downloads/see-version.json':
        resp.headers['Access-Control-Allow-Origin'] = '*'
    return resp


CFG_PATH = os.path.join(ROOT, 'data', 'gw-config.json')
KEY_PATH = os.path.join(ROOT, 'data', 'api-key.txt')


def _api_key():
    try:
        with open(KEY_PATH, encoding='utf-8') as f:
            k = f.read().strip()
        if k:
            return k
    except Exception:  # noqa: BLE001
        pass
    import secrets as _s
    k = _s.token_hex(16)
    os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
    with open(KEY_PATH, 'w', encoding='utf-8') as f:
        f.write(k)
    try:
        os.chmod(KEY_PATH, 0o600)
    except Exception:  # noqa: BLE001
        pass
    return k


def _load_gwcfg():
    try:
        with open(CFG_PATH, encoding='utf-8') as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return {}


def _save_gwcfg(cfg):
    os.makedirs(os.path.dirname(CFG_PATH), exist_ok=True)
    tmp = CFG_PATH + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, ensure_ascii=False)
    try:
        os.chmod(tmp, 0o600)
    except Exception:  # noqa: BLE001
        pass
    os.replace(tmp, CFG_PATH)


# ---------- 鉴权：机器密钥（只给采集器）+ 网页会话（口令登录）----------
# 背景：以前网页里内嵌一把万能密钥（谁看源码都能拿到）→ 能读到网关管理员密码。
# 现在拆成两层：公开产物里一个密钥都不留；网页/App 靠用户口令换会话令牌。
UIPASS_PATH = os.path.join(ROOT, 'data', 'ui-pass.json')
SESS_PATH = os.path.join(ROOT, 'data', 'sessions.json')
LOGIN_FAIL = {}
SESSION_TTL = 90 * 86400


def _opt(methods='GET, POST, OPTIONS'):
    resp = jsonify(ok=True)
    resp.headers['Access-Control-Allow-Methods'] = methods
    return resp


def _hash_pass(pw, salt=None):
    salt = salt or secrets.token_hex(8)
    h = hashlib.pbkdf2_hmac('sha256', pw.encode('utf-8'), bytes.fromhex(salt), 120000)
    return salt, h.hex()


def _load_uipass():
    try:
        with open(UIPASS_PATH, encoding='utf-8') as f:
            d = json.load(f)
        if d.get('salt') and d.get('hash'):
            return d
    except Exception:  # noqa: BLE001
        pass
    return None


def _save_uipass(pw):
    salt, h = _hash_pass(pw)
    tmp = UIPASS_PATH + '.tmp'
    os.makedirs(os.path.dirname(UIPASS_PATH), exist_ok=True)
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump({'salt': salt, 'hash': h, 'set_ts': int(time.time())}, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, UIPASS_PATH)


def _check_pass(pw):
    d = _load_uipass()
    if not d or not pw:
        return False
    _, h = _hash_pass(pw, d['salt'])
    return hmac.compare_digest(h, d['hash'])


def _load_sessions():
    try:
        with open(SESS_PATH, encoding='utf-8') as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _save_sessions(d):
    now = int(time.time())
    d = {k: v for k, v in d.items() if int(v.get('exp', 0)) > now}
    os.makedirs(os.path.dirname(SESS_PATH), exist_ok=True)
    tmp = SESS_PATH + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(d, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, SESS_PATH)


def _new_session():
    tok = secrets.token_hex(24)
    d = _load_sessions()
    d[tok] = {'exp': int(time.time()) + SESSION_TTL, 'ts': int(time.time()),
              'ip': (request.headers.get('X-Real-IP') or request.remote_addr or '')[:45],
              'ua': (request.headers.get('User-Agent') or '')[:120]}
    _save_sessions(d)
    return tok


def _client_ip():
    return (request.headers.get('X-Real-IP') or request.remote_addr or '')[:45]


def _auth_kind():
    """'key' = 采集器机器密钥；'sess' = 网页/App 会话令牌；None = 匿名。"""
    k = (request.headers.get('X-See-Key') or request.args.get('key') or '').strip()
    if k and hmac.compare_digest(k, _api_key()):
        return 'key'
    tok = (request.headers.get('X-See-Session') or request.args.get('sess') or '').strip()
    if tok:
        s = _load_sessions().get(tok)
        if s and int(s.get('exp', 0)) > time.time():
            return 'sess'
    return None


def _deny():
    return jsonify(ok=False, error='unauthorized'), 401


def _public_cfg(cfg):
    """给网页/App 的配置：网关密码只报「有没有、几位」，永不回明文。"""
    out = dict(cfg)
    p = out.pop('pass', '') or ''
    out['has_pass'] = bool(p)
    out['pass_len'] = len(p)
    return out


def _login_blocked(ip):
    c = LOGIN_FAIL.get(ip)
    return bool(c and time.time() - c[1] < 300 and c[0] >= 8)


def _login_failed(ip):
    now = time.time()
    c = LOGIN_FAIL.get(ip)
    if not c or now - c[1] > 300:
        LOGIN_FAIL[ip] = [1, now]
    else:
        c[0] += 1


# ---------- 登录 / 会话 ----------

@app.route('/api/session', methods=['OPTIONS', 'GET'])
def api_session():
    if request.method == 'OPTIONS':
        return _opt('GET, OPTIONS')
    kind = _auth_kind()
    return jsonify(ok=True, authed=bool(kind), kind=kind or '',
                   need_setup=(_load_uipass() is None))


@app.route('/api/setup', methods=['OPTIONS', 'POST'])
def api_setup():
    """首次设置访问口令（只允许设一次，原子占位）。"""
    if request.method == 'OPTIONS':
        return _opt('POST, OPTIONS')
    data = request.get_json(force=True, silent=True) or {}
    pw = (data.get('pass') or '').strip()
    if len(pw) < 6:
        return jsonify(ok=False, error='口令至少 6 位'), 400
    try:
        fd = os.open(UIPASS_PATH + '.lock', os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(fd)
    except FileExistsError:
        return jsonify(ok=False, error='口令已经设置过了'), 403
    except Exception:  # noqa: BLE001
        pass
    _save_uipass(pw)
    return jsonify(ok=True, token=_new_session())


@app.route('/api/login', methods=['OPTIONS', 'POST'])
def api_login():
    if request.method == 'OPTIONS':
        return _opt('POST, OPTIONS')
    ip = _client_ip()
    if _login_blocked(ip):
        return jsonify(ok=False, error='失败次数过多，请 5 分钟后再试'), 429
    if _load_uipass() is None:
        return jsonify(ok=False, error='还没有设置访问口令', need_setup=True), 403
    data = request.get_json(force=True, silent=True) or {}
    if not _check_pass((data.get('pass') or '').strip()):
        _login_failed(ip)
        return jsonify(ok=False, error='口令错误'), 401
    LOGIN_FAIL.pop(ip, None)
    return jsonify(ok=True, token=_new_session())


@app.route('/api/logout', methods=['OPTIONS', 'POST'])
def api_logout():
    if request.method == 'OPTIONS':
        return _opt('POST, OPTIONS')
    tok = (request.headers.get('X-See-Session') or '').strip()
    if tok:
        d = _load_sessions()
        d.pop(tok, None)
        _save_sessions(d)
    return jsonify(ok=True)


@app.route('/api/session/all', methods=['OPTIONS', 'POST'])
def api_session_kill():
    """退出所有设备。"""
    if request.method == 'OPTIONS':
        return _opt('POST, OPTIONS')
    if _auth_kind() != 'sess':
        return _deny()
    _save_sessions({})
    return jsonify(ok=True)


@app.route('/api/machine-key', methods=['OPTIONS', 'GET'])
def api_machine_key():
    """登录后才给看：采集器（微服）要用的机器密钥。"""
    if request.method == 'OPTIONS':
        return _opt('GET, OPTIONS')
    if _auth_kind() != 'sess':
        return _deny()
    return jsonify(ok=True, key=_api_key())


@app.route('/api/config', methods=['OPTIONS', 'GET', 'POST'])
def api_config():
    if request.method == 'OPTIONS':
        return _opt('GET, POST, OPTIONS')
    kind = _auth_kind()
    if kind is None:
        return _deny()
    if request.method == 'GET':
        cfg = _load_gwcfg()
        # 只有采集器（机器密钥）能拿到明文密码；网页/App 只知道「有没有、几位」
        return jsonify(ok=True, cfg=(cfg if kind == 'key' else _public_cfg(cfg)))
    data = request.get_json(force=True, silent=True) or {}
    cfg = _load_gwcfg()
    for k in ('ip', 'user', 'on', 'anDev', 'anWin'):
        if k in data:
            cfg[k] = data[k]
    # 密码是「只写不读」：传空字符串表示不动它
    if (data.get('pass') or '') != '':
        cfg['pass'] = data['pass']
    _save_gwcfg(cfg)
    return jsonify(ok=True, cfg=(cfg if kind == 'key' else _public_cfg(cfg)))


# ---------- 网关设备流量采样（app 上传 / 网页读取）----------

@app.route('/api/gw/samples', methods=['OPTIONS', 'POST'])
def api_gw_samples():
    if request.method == 'OPTIONS':
        return _opt('POST, OPTIONS')
    if _auth_kind() != 'key':
        return _deny()
    data = request.get_json(force=True, silent=True) or {}
    rows = data.get('samples') or []
    n = store.add_gw_samples(rows[:2000])
    # 顺带清理 30 天前的采样
    try:
        if time.time() - _LAST_PRUNE[0] > 3600:
            _LAST_PRUNE[0] = time.time()
            store.prune_gw_samples(int(time.time()) - 30 * 86400)
    except Exception:  # noqa: BLE001
        pass
    return jsonify(ok=True, n=n)


@app.route('/api/gw/devices', methods=['OPTIONS', 'GET'])
def api_gw_devices():
    """监控页数据源：采集器最近一轮的设备快照。

    手机端不再登网关，监控页改成读这份数据（网页/app 同一份口径）。
    """
    if request.method == 'OPTIONS':
        return _opt('GET, OPTIONS')
    if _auth_kind() is None:
        return _deny()
    now = int(time.time())
    try:
        devs = store.gw_latest(now - 900)
    except Exception as e:  # noqa: BLE001
        return jsonify(ok=False, error='读取采样失败：%s' % str(e)[:120]), 500
    try:
        links = store.gw_last_link()
    except Exception:  # noqa: BLE001
        links = {}
    for d in devs:
        if not d.get('link'):
            d['link'] = links.get(d['key'], '')
    wired = [d for d in devs if d.get('link') == 'wired']
    wireless = [d for d in devs if d.get('link') == 'wifi']
    age = (now - max([d['ts'] for d in devs])) if devs else -1
    totals = {
        'wdown': sum(d['down'] for d in wired), 'wup': sum(d['up'] for d in wired),
        'wldown': sum(d['down'] for d in wireless), 'wlup': sum(d['up'] for d in wireless),
        'wired': len(wired), 'wireless': len(wireless),
    }
    return jsonify(ok=True, ts=now, age=age, src='collector', devices=devs, totals=totals)


@app.route('/api/gw/cred', methods=['OPTIONS', 'GET'])
def api_gw_cred():
    """采集器专用：取网关登录凭据（含明文密码）。仅机器密钥可用。"""
    if request.method == 'OPTIONS':
        return _opt('GET, OPTIONS')
    if _auth_kind() != 'key':
        return _deny()
    cfg = _load_gwcfg()
    return jsonify(ok=True, ip=cfg.get('ip') or '', user=cfg.get('user') or '',
                   **{'pass': cfg.get('pass') or ''}, on=bool(cfg.get('on')),
                   anDev=cfg.get('anDev') or '', anWin=cfg.get('anWin') or 24)


@app.route('/api/gw/keys', methods=['OPTIONS', 'GET'])
def api_gw_keys():
    if request.method == 'OPTIONS':
        return _opt('GET, OPTIONS')
    if _auth_kind() is None:
        return _deny()
    days = int(request.args.get('days', 7))
    now = int(time.time())
    keys = store.gw_keys(now - days * 86400)
    return jsonify(ok=True, now=now, keys=keys)


@app.route('/api/gw/series', methods=['OPTIONS', 'GET'])
def api_gw_series():
    if request.method == 'OPTIONS':
        return _opt('GET, OPTIONS')
    if _auth_kind() is None:
        return _deny()
    key = (request.args.get('dev') or '').strip()
    hours = max(1, min(int(request.args.get('hours', 24)), 72))
    if not key:
        return jsonify(ok=False, error='未指定设备'), 400
    now = int(time.time())
    # 分时桶对齐整点：末端取当前整点的下一个整点，向前推 hours 个整点，
    # 这样每格都是天然的 1 小时（如 11:00–12:00），而不是 now-24h 的滚动偏移。
    end = (now // 3600) * 3600 + 3600
    frm = end - hours * 3600
    n = hours * 60
    speed = [0.0] * n
    cnt = [0] * n
    pres = [0] * n
    has = [0] * n
    name = ''
    ip = ''
    for r in store.gw_series(key, frm, end):
        m = (int(r['ts']) - frm) // 60
        if m < 0 or m >= n:
            continue
        has[m] = 1
        if r['present']:
            pres[m] = 1
            speed[m] += float(r['up'] or 0) + float(r['down'] or 0)
            cnt[m] += 1
    for i in range(n):
        if cnt[i]:
            speed[i] = speed[i] / cnt[i]
    for k in store.gw_keys(frm):
        if k['key'] == key:
            name = k.get('name') or ''
            ip = k.get('ip') or ''
    return jsonify(ok=True, key=key, name=name, ip=ip, frm=frm, now=now, end=end, minutes=n,
                   speed=speed, present=pres, has=has)


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


@app.route('/api/gw/plan', methods=['OPTIONS', 'POST'])
def api_gw_plan():
    if request.method == 'OPTIONS':
        return _opt('POST, OPTIONS')
    if _auth_kind() is None:
        return _deny()
    try:
        with open(os.path.join(ROOT, 'data', 'gw-plan.json'), encoding='utf-8') as f:
            plan = json.load(f)
    except Exception:
        plan = {'steps': []}
    resp = jsonify(plan)
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Cache-Control'] = 'no-store'
    return resp


@app.route('/api/gw/report', methods=['OPTIONS'])
def api_gw_report_options():
    return _opt('POST, OPTIONS')


@app.post('/api/gw/report')
def api_gw_report():
    if _auth_kind() is None:
        return _deny()
    data = request.get_json(force=True, silent=True) or {}
    try:
        with open(os.path.join(ROOT, 'data', 'gw-probes.log'), 'a', encoding='utf-8') as f:
            f.write(json.dumps({'ts': int(time.time()), 'data': data}, ensure_ascii=False) + '\n')
    except Exception:
        pass
    return jsonify(ok=True)


@app.post('/api/snapshots/ocr')
def api_snap_ocr():
    if _auth_kind() is None:
        return _deny()
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
