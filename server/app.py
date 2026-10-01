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
PREF_PATH = os.path.join(ROOT, 'data', 'ui-prefs.json')
# 允许存到后端的界面偏好（白名单，值是类型），换设备登录也认这份
PREF_KEYS = {'hour_desc': bool, 'obsSrc': str}   # obsSrc: collector|local（观察页数据源）
KEY_PATH = os.path.join(ROOT, 'data', 'api-key.txt')
# 换密钥时的过渡：旧密钥放这里，只在 KEY_GRACE_HOURS 内认（到期自动作废，文件不用删）
KEY_PREV_PATH = os.path.join(ROOT, 'data', 'api-key.prev')
KEY_GRACE_HOURS = 72


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


LINK_OV_PATH = os.path.join(ROOT, 'data', 'gw-link-overrides.json')

# 这些品类的设备只可能是无线接入；网关把它们记成「有线」，多半是挂在
# 子路由/AP（如 华为路由BE7）的 WiFi 下 —— 默认按无线显示，还可以再手动改。
_WIFI_ONLY_KEYS = (
    '音箱', '音响', '智能屏', '插座', '摄像头', '摄像机', '门铃',
    '扫地', '拖扫', '扫拖', '吸尘', '机器人', '冰箱', '冷柜', '冰柜',
    '洗衣机', '干衣', '空调', '电视', '投影', '净化', '加湿', '风扇',
    '窗帘', '灯', '开关', '传感器', '门锁', '热水', '净水', '马桶',
    '体重秤', '手环', '手表', '手机', 'phone',
)


def _wifi_only_default(name):
    n = str(name or '').lower()
    return any(k in n for k in _WIFI_ONLY_KEYS)


def _load_link_ov():
    try:
        with open(LINK_OV_PATH, encoding='utf-8') as f:
            j = json.load(f)
        return j if isinstance(j, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _save_link_ov(ov):
    os.makedirs(os.path.dirname(LINK_OV_PATH), exist_ok=True)
    tmp = LINK_OV_PATH + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(ov, f, ensure_ascii=False)
    try:
        os.chmod(tmp, 0o600)
    except Exception:  # noqa: BLE001
        pass
    os.replace(tmp, LINK_OV_PATH)


AP_OV_PATH = os.path.join(ROOT, 'data', 'gw-ap-assign.json')


def _load_ap_ov():
    try:
        with open(AP_OV_PATH, encoding='utf-8') as f:
            j = json.load(f)
        return j if isinstance(j, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _save_ap_ov(ov):
    os.makedirs(os.path.dirname(AP_OV_PATH), exist_ok=True)
    tmp = AP_OV_PATH + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(ov, f, ensure_ascii=False)
    try:
        os.chmod(tmp, 0o600)
    except Exception:  # noqa: BLE001
        pass
    os.replace(tmp, AP_OV_PATH)


MERGE_PATH = os.path.join(ROOT, 'data', 'gw-merge.json')


def _load_merge_file():
    """{'split': [不参与同名合并的键], 'merge': {手动指定合并}}；兼容旧格式 {成员:主体}。"""
    try:
        with open(MERGE_PATH, encoding='utf-8') as f:
            j = json.load(f)
    except Exception:  # noqa: BLE001
        return {'split': [], 'merge': {}}
    if isinstance(j, dict) and ('split' in j or 'merge' in j):
        return {'split': [str(x) for x in (j.get('split') or [])],
                'merge': {str(a): str(b) for a, b in (j.get('merge') or {}).items() if a and b and a != b}}
    return {'split': [], 'merge': {str(a): str(b) for a, b in j.items() if a and b and a != b}}


def _save_merge_file(cfg2):
    os.makedirs(os.path.dirname(MERGE_PATH), exist_ok=True)
    tmp = MERGE_PATH + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(cfg2, f, ensure_ascii=False)
    try:
        os.chmod(tmp, 0o600)
    except Exception:  # noqa: BLE001
        pass
    os.replace(tmp, MERGE_PATH)
    _MERGE_CACHE[0] = 0.0     # 立刻失效重算


_MERGE_CACHE = [0.0, {}]


def _merge_map():
    """同名设备缺省合并：同名组里最近活跃的当主体、其余并进去（主网关同一台设备换 IP 后
    历史不再被拆开）；split 名单里的键除外，merge 里的手动指定最优先。60s 缓存。"""
    now = time.time()
    if now - _MERGE_CACHE[0] < 60:
        return dict(_MERGE_CACHE[1])
    mf = _load_merge_file()
    splits = set(mf['split'])
    m = {}
    try:
        keys = store.gw_keys(int(now) - 30 * 86400)
    except Exception:  # noqa: BLE001
        keys = []
    groups = {}
    nm_ov = _load_names()
    for k in keys:
        nm = (nm_ov.get(k['key']) or k.get('name') or '').strip()
        if nm:
            groups.setdefault(nm, []).append(k)
    for ks in groups.values():
        if len(ks) < 2:
            continue
        ks = sorted(ks, key=lambda x: -x.get('last_ts', 0))
        canon = ks[0]['key']
        for k in ks[1:]:
            if k['key'] not in splits:
                m[k['key']] = canon
    m.update(mf['merge'])
    _MERGE_CACHE[0] = now
    _MERGE_CACHE[1] = m
    return dict(m)


def _merge_keys(m, key):
    """key 以及挂在它名下的所有成员（含传递链，防 A→B、B→C）。"""
    out = [key]
    grew = True
    while grew:
        grew = False
        for mem, canon in m.items():
            if canon in out and mem not in out:
                out.append(mem)
                grew = True
    return out


def _merge_rows(m, key, frm, to):
    """key+成员的采样按 ts 合并：同一时刻多行优先在线那条（正常换 IP 不重叠，兜底）。"""
    rows = []
    for kk in _merge_keys(m, key):
        try:
            rows.extend(store.gw_series(kk, frm, to))
        except Exception:  # noqa: BLE001
            pass
    rows.sort(key=lambda r: int(r['ts']))
    out = []
    for r in rows:
        t = int(r['ts'])
        if out and int(out[-1]['ts']) == t:
            if r['present'] and not out[-1]['present']:
                out[-1] = r
            continue
        out.append(r)
    return out


NAME_OV_PATH = os.path.join(ROOT, 'data', 'gw-names.json')


def _load_names():
    # 手动改的设备显示名（覆盖网关返回的名字）
    try:
        with open(NAME_OV_PATH, encoding='utf-8') as f:
            j = json.load(f)
        return {str(a): str(b)[:24] for a, b in j.items() if a and b}
    except Exception:  # noqa: BLE001
        return {}


def _save_names(m):
    os.makedirs(os.path.dirname(NAME_OV_PATH), exist_ok=True)
    tmp = NAME_OV_PATH + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(m, f, ensure_ascii=False)
    try:
        os.chmod(tmp, 0o600)
    except Exception:  # noqa: BLE001
        pass
    os.replace(tmp, NAME_OV_PATH)
    _MERGE_CACHE[0] = 0.0     # 改名影响同名分组，立即重算


OFF_MAX_MIN = 1440          # 「暂停 N 分钟」上限（24 小时）


def _eff_on(cfg):
    """采集总开关的有效值。

    cfg.on=False 且 cfg.offUntil>0 表示「暂停到那个时间点自动恢复」；
    到期后这里自动把 on 拧回 True 并清掉 offUntil（并落盘），
    这样采集器不需要自己做定时逻辑，网页刷新也能看到已经恢复。
    """
    off = float(cfg.get('offUntil') or 0)
    if cfg.get('on'):
        if off:
            cfg['offUntil'] = 0
            _save_gwcfg(cfg)
        return True
    if off and time.time() >= off:
        cfg['on'] = True
        cfg['offUntil'] = 0
        _save_gwcfg(cfg)
        return True
    return False


# ---------- 鉴权：机器密钥（只给采集器）+ 网页会话（口令登录）----------
# 背景：以前网页里内嵌一把万能密钥（谁看源码都能拿到）→ 能读到网关管理员密码。
# 现在拆成两层：公开产物里一个密钥都不留；网页/App 靠用户口令换会话令牌。
UIPASS_PATH = os.path.join(ROOT, 'data', 'ui-pass.json')
SESS_PATH = os.path.join(ROOT, 'data', 'sessions.json')
LOGIN_FAIL = {}
# 会话不设过期：一台设备登录一次就一直有效，只有「改口令（全端重登）」或主动退出才失效。
# 0 = 永不过期（只有设备自己把令牌弄丢了才会重新登录）。
SESSION_TTL = 0


def _sess_ok(s):
    """会话是否有效：exp=0 表示永久。"""
    if not isinstance(s, dict):
        return False
    exp = int(s.get('exp', 0) or 0)
    return exp == 0 or exp > time.time()


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
    d = {k: v for k, v in d.items() if _sess_ok(v)}
    os.makedirs(os.path.dirname(SESS_PATH), exist_ok=True)
    tmp = SESS_PATH + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(d, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, SESS_PATH)


def _new_session():
    tok = secrets.token_hex(24)
    d = _load_sessions()
    d[tok] = {'exp': (int(time.time()) + SESSION_TTL) if SESSION_TTL else 0, 'ts': int(time.time()),
              'ip': (request.headers.get('X-Real-IP') or request.remote_addr or '')[:45],
              'ua': (request.headers.get('User-Agent') or '')[:120]}
    _save_sessions(d)
    return tok


def _client_ip():
    return (request.headers.get('X-Real-IP') or request.remote_addr or '')[:45]


def _key_ok(k):
    """机器密钥校验：当前密钥，或过渡期内的旧密钥（api-key.prev，按文件时间自动过期）。"""
    if not k:
        return False
    if hmac.compare_digest(k, _api_key()):
        return True
    try:
        age = time.time() - os.path.getmtime(KEY_PREV_PATH)
        if age > KEY_GRACE_HOURS * 3600:
            return False
        with open(KEY_PREV_PATH, encoding='utf-8') as f:
            prev = f.read().strip()
        return bool(prev) and hmac.compare_digest(k, prev)
    except Exception:  # noqa: BLE001
        return False


def _auth_kind():
    """'key' = 采集器机器密钥；'sess' = 网页/App 会话令牌；None = 匿名。"""
    k = (request.headers.get('X-See-Key') or request.args.get('key') or '').strip()
    if _key_ok(k):
        return 'key'
    tok = (request.headers.get('X-See-Session') or request.args.get('sess') or '').strip()
    if tok:
        if _sess_ok(_load_sessions().get(tok)):
            return 'sess'
    return None


def _deny():
    return jsonify(ok=False, error='unauthorized'), 401


def _load_prefs():
    try:
        with open(PREF_PATH, encoding='utf-8') as f:
            d = json.load(f)
        if not isinstance(d, dict):
            return {}
        return {k: v for k, v in d.items() if k in PREF_KEYS and isinstance(v, PREF_KEYS[k])}
    except Exception:  # noqa: BLE001
        return {}


def _save_prefs(d):
    os.makedirs(os.path.dirname(PREF_PATH), exist_ok=True)
    tmp = PREF_PATH + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(d, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, PREF_PATH)


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


@app.route('/api/pass', methods=['OPTIONS', 'POST'])
def api_pass():
    """改访问口令：必须已登录，且要带原口令校验。"""
    if request.method == 'OPTIONS':
        return _opt('POST, OPTIONS')
    if _auth_kind() != 'sess':
        return _deny()
    ip = _client_ip()
    if _login_blocked(ip):
        return jsonify(ok=False, error='失败次数过多，请 5 分钟后再试'), 429
    data = request.get_json(force=True, silent=True) or {}
    cur = (data.get('cur') or '').strip()
    new = (data.get('new') or '').strip()
    if not _check_pass(cur):
        _login_failed(ip)
        return jsonify(ok=False, error='原口令不对'), 401
    if len(new) < 6:
        return jsonify(ok=False, error='新口令至少 6 位'), 400
    if new == cur:
        return jsonify(ok=False, error='新口令和原口令一样'), 400
    LOGIN_FAIL.pop(ip, None)
    _save_uipass(new)
    # 口令变了 → 所有设备的旧令牌立即作废（别的设备要重新登录）；
    # 改口令的这台设备当场换发新令牌，不用重登。
    _save_sessions({})
    return jsonify(ok=True, token=_new_session())


@app.route('/api/session/all', methods=['OPTIONS', 'POST'])
def api_session_kill():
    """退出所有设备。"""
    if request.method == 'OPTIONS':
        return _opt('POST, OPTIONS')
    if _auth_kind() != 'sess':
        return _deny()
    _save_sessions({})
    return jsonify(ok=True)


@app.route('/api/prefs', methods=['OPTIONS', 'GET', 'POST'])
def api_prefs():
    """界面偏好存后端：登录后可见可改，换设备/重登都认这份。"""
    if request.method == 'OPTIONS':
        return _opt('GET, POST, OPTIONS')
    kind = _auth_kind()
    if kind is None:
        return _deny()
    if request.method == 'GET':
        return jsonify(ok=True, prefs=_load_prefs())
    if kind != 'sess':
        return _deny()
    data = request.get_json(force=True, silent=True) or {}
    k = data.get('key')
    if k not in PREF_KEYS:
        return jsonify(ok=False, error='不认识的偏好项'), 400
    v = data.get('value')
    if not isinstance(v, PREF_KEYS[k]):
        return jsonify(ok=False, error='值类型不对'), 400
    d = _load_prefs()
    d[k] = v
    _save_prefs(d)
    return jsonify(ok=True, prefs=d)


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
        out = cfg if kind == 'key' else _public_cfg(cfg)
        out['on'] = _eff_on(cfg)                 # 开关报「有效值」（自动恢复后就是 True）
        out['off_until'] = int(float(cfg.get('offUntil') or 0))
        last = store.gw_last_ts()
        return jsonify(ok=True, cfg=out, now=int(time.time()),
                       last_sample=last, sample_age=(int(time.time() - last) if last else -1))
    data = request.get_json(force=True, silent=True) or {}
    cfg = _load_gwcfg()
    for k in ('ip', 'user', 'on', 'anDev', 'anWin'):
        if k in data:
            cfg[k] = bool(data[k]) if k == 'on' else data[k]
    # offMin：暂停多少分钟后自动恢复（0 或没传 = 一直停到手动恢复）
    try:
        off_min = int(data.get('offMin') or 0)
    except Exception:  # noqa: BLE001
        off_min = 0
    off_min = max(0, min(off_min, OFF_MAX_MIN))
    cfg['offUntil'] = (time.time() + off_min * 60) if (not cfg.get('on') and off_min) else 0
    # 密码是「只写不读」：传空字符串表示不动它
    if (data.get('pass') or '') != '':
        cfg['pass'] = data['pass']
    _save_gwcfg(cfg)
    out = cfg if kind == 'key' else _public_cfg(cfg)
    out['on'] = _eff_on(cfg)
    out['off_until'] = int(float(cfg.get('offUntil') or 0))
    return jsonify(ok=True, cfg=out)


# ---------- 网关设备流量采样（app 上传 / 网页读取）----------

@app.route('/api/obs/report', methods=['OPTIONS', 'POST'])
def api_obs_report():
    """采集器上报的局域网发现（观察页数据源：MAC/厂商/在线）。仅机器密钥。"""
    if request.method == 'OPTIONS':
        return _opt('POST, OPTIONS')
    if _auth_kind() != 'key':
        return _deny()
    data = request.get_json(force=True, silent=True) or {}
    rows = data.get('devices') or []
    if not isinstance(rows, list):
        return jsonify(ok=False, error='devices 应为数组'), 400
    n = scanner.apply_report(rows[:512])
    return jsonify(ok=True, n=n)


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
    m = _merge_map()
    if m:
        by = {}
        for d in devs:
            kk = m.get(d['key'], d['key'])
            d['key'] = kk
            o = by.get(kk)
            if o is None or d['ts'] > o['ts']:
                by[kk] = d
        devs = sorted(by.values(), key=lambda d: -d['ts'])
    nm_ov = _load_names()
    if nm_ov:
        for d in devs:
            if d.get('key') in nm_ov:
                d['name'] = nm_ov[d['key']]
    try:
        links = store.gw_last_link()
    except Exception:  # noqa: BLE001
        links = {}
    ov = _load_link_ov()
    for d in devs:
        if not d.get('link'):
            d['link'] = links.get(d['key'], '')
        d['link_raw'] = d.get('link') or ''   # 网关原始口径：拓扑图判断「挂在 AP 下」用
        if d.get('link') != 'wifi' and _wifi_only_default(d.get('name')):
            d['link'] = 'wifi'          # 只可能无线的品类：挂在子路由/AP 下也按无线
        if d.get('key') in ov:
            d['link'] = ov[d['key']]    # 手动指定的最优先
            d['link_fixed'] = 1
    aov = _load_ap_ov()
    for d in devs:
        if d.get('key') in aov:
            d['ap'] = aov[d['key']]     # 手动指定挂在哪台 AP 下（拓扑分层用）
            d['ap_fixed'] = 1
    wired = [d for d in devs if d.get('link') == 'wired']
    wireless = [d for d in devs if d.get('link') == 'wifi']
    age = (now - max([d['ts'] for d in devs])) if devs else -1
    totals = {
        'wdown': sum(d['down'] for d in wired), 'wup': sum(d['up'] for d in wired),
        'wldown': sum(d['down'] for d in wireless), 'wlup': sum(d['up'] for d in wireless),
        'wired': len(wired), 'wireless': len(wireless),
    }
    return jsonify(ok=True, ts=now, age=age, src='collector', devices=devs, totals=totals)


@app.route('/api/gw/link', methods=['OPTIONS', 'POST'])
def api_gw_link():
    """手动指定某台设备的有线/无线；link 为空 = 恢复自动判定。"""
    if request.method == 'OPTIONS':
        return _opt('POST, OPTIONS')
    if _auth_kind() is None:
        return _deny()
    data = request.get_json(force=True, silent=True) or {}
    key = str(data.get('key') or '').strip()[:64]
    link = str(data.get('link') or '')
    if not key:
        return jsonify(ok=False, error='缺少设备标识'), 400
    if link not in ('', 'wifi', 'wired'):
        return jsonify(ok=False, error='link 只能是 wifi / wired / 空字符串'), 400
    ov = _load_link_ov()
    if link:
        ov[key] = link
    else:
        ov.pop(key, None)
    _save_link_ov(ov)
    return jsonify(ok=True, key=key, link=link)


@app.route('/api/gw/ap', methods=['OPTIONS', 'POST'])
def api_gw_ap():
    """手动指定某台设备挂在哪台 AP 下（ap 为空 = 未指定）。"""
    if request.method == 'OPTIONS':
        return _opt('POST, OPTIONS')
    if _auth_kind() is None:
        return _deny()
    data = request.get_json(force=True, silent=True) or {}
    key = str(data.get('key') or '').strip()[:64]
    ap = str(data.get('ap') or '').strip()[:64]
    if not key:
        return jsonify(ok=False, error='缺少设备标识'), 400
    ov = _load_ap_ov()
    if ap:
        ov[key] = ap
    else:
        ov.pop(key, None)
    _save_ap_ov(ov)
    return jsonify(ok=True, key=key, ap=ap)


@app.route('/api/gw/name', methods=['OPTIONS', 'GET'])
def api_gw_name():
    # 手动改的设备名表
    if request.method == 'OPTIONS':
        return _opt('GET, OPTIONS')
    if _auth_kind() is None:
        return _deny()
    return jsonify(ok=True, map=_load_names())


@app.route('/api/gw/name/set', methods=['OPTIONS', 'POST'])
def api_gw_name_set():
    # 手动改设备显示名（name 为空 = 恢复网关名）；改名会让同名合并按新名字重新分组
    if request.method == 'OPTIONS':
        return _opt('POST, OPTIONS')
    if _auth_kind() is None:
        return _deny()
    data = request.get_json(force=True, silent=True) or {}
    key = str(data.get('key') or '').strip()[:64]
    name = str(data.get('name') or '').strip()[:24]
    if not key:
        return jsonify(ok=False, error='缺少设备标识'), 400
    m = _load_names()
    if name:
        m[key] = name
    else:
        m.pop(key, None)
    _save_names(m)
    return jsonify(ok=True, key=key, name=name)


@app.route('/api/gw/cred', methods=['OPTIONS', 'GET'])
def api_gw_cred():
    """采集器专用：取网关登录凭据（含明文密码）。仅机器密钥可用。"""
    if request.method == 'OPTIONS':
        return _opt('GET, OPTIONS')
    if _auth_kind() != 'key':
        return _deny()
    cfg = _load_gwcfg()
    return jsonify(ok=True, ip=cfg.get('ip') or '', user=cfg.get('user') or '',
                   **{'pass': cfg.get('pass') or ''}, on=_eff_on(cfg),
                   anDev=cfg.get('anDev') or '', anWin=cfg.get('anWin') or 24)


@app.route('/api/gw/on', methods=['OPTIONS', 'GET'])
def api_gw_on():
    """采集器专用的极简开关口：只回 on，不含任何凭据。

    整配置（含密码）还是每 5 分钟拉一次；采集器另用这个口每 20 秒对一次，
    这样「暂停/恢复」在最坏 20 秒内生效，而不是等 5 分钟。
    """
    if request.method == 'OPTIONS':
        return _opt('GET, OPTIONS')
    if _auth_kind() != 'key':
        return _deny()
    cfg = _load_gwcfg()
    return jsonify(ok=True, on=_eff_on(cfg), now=int(time.time()))


@app.route('/api/gw/keys', methods=['OPTIONS', 'GET'])
def api_gw_keys():
    if request.method == 'OPTIONS':
        return _opt('GET, OPTIONS')
    if _auth_kind() is None:
        return _deny()
    days = int(request.args.get('days', 7))
    now = int(time.time())
    keys = store.gw_keys(now - days * 86400)
    m = _merge_map()
    if m:
        by = {}
        for k in keys:
            kk = m.get(k['key'], k['key'])
            o = by.get(kk)
            if o is None:
                k2 = dict(k)
                k2['key'] = kk
                by[kk] = k2
            else:
                o['last_ts'] = max(o.get('last_ts', 0), k.get('last_ts', 0))
                if not o.get('name') and k.get('name'):
                    o['name'] = k['name']
        keys = sorted(by.values(), key=lambda x: -x.get('last_ts', 0))
    nm_ov = _load_names()
    if nm_ov:
        for k in keys:
            if k.get('key') in nm_ov:
                k['name'] = nm_ov[k['key']]
                k['name_fixed'] = 1
    return jsonify(ok=True, now=now, keys=keys)


@app.route('/api/gw/merge', methods=['OPTIONS', 'GET'])
def api_gw_merge():
    """同名设备分组 + 缺省合并状态（设置页「同名设备合并」用）。"""
    if request.method == 'OPTIONS':
        return _opt('GET, OPTIONS')
    if _auth_kind() is None:
        return _deny()
    now = int(time.time())
    keys = store.gw_keys(now - 30 * 86400)
    mf = _load_merge_file()
    splits = set(mf['split'])
    groups = {}
    nm_ov = _load_names()
    for k in keys:
        nm = (nm_ov.get(k['key']) or k.get('name') or '').strip()
        if nm:
            groups.setdefault(nm, []).append(k)
    out = []
    for nm, ks in groups.items():
        if len(ks) < 2:
            continue
        ks = sorted(ks, key=lambda x: -x.get('last_ts', 0))
        items = [{'key': k['key'], 'ip': k.get('ip') or k['key'],
                  'last_ts': int(k.get('last_ts') or 0),
                  'active': int(k.get('last_ts') or 0) >= now - 1800,
                  'split': k['key'] in splits} for k in ks]
        out.append({'name': nm, 'items': items, 'canonical': ks[0]['key'],
                    'merged': any(not i['split'] for i in items[1:]),
                    'overlap': sum(1 for i in items if i['active']) > 1})
    return jsonify(ok=True, groups=out, split=sorted(splits), merge=mf['merge'])


@app.route('/api/gw/merge/set', methods=['OPTIONS', 'POST'])
def api_gw_merge_set():
    """同名缺省合并的例外管理：on=false 拆分这组（成员进 split 名单）；on=true 恢复默认合并。"""
    if request.method == 'OPTIONS':
        return _opt('POST, OPTIONS')
    if _auth_kind() is None:
        return _deny()
    data = request.get_json(force=True, silent=True) or {}
    keys = [str(k)[:64] for k in (data.get('keys') or []) if k]
    keys = [k for k in dict.fromkeys(keys)]
    if len(keys) < 2:
        return jsonify(ok=False, error='至少要两台设备'), 400
    mf = _load_merge_file()
    splits = set(mf['split'])
    if data.get('on'):
        for k in keys:
            splits.discard(k)
    else:
        for k in keys[1:]:            # 成员进 split 名单（主体不需要）
            splits.add(k)
    for k in keys:
        mf['merge'].pop(k, None)
    mf['split'] = sorted(splits)
    _save_merge_file(mf)
    return jsonify(ok=True, keys=keys, on=bool(data.get('on')), split=mf['split'], merge=mf['merge'])


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
    sup = [0.0] * n   # 上行均值（图表下半段用下行、上半段用上行）
    sdn = [0.0] * n   # 下行均值
    cnt = [0] * n
    pres = [0] * n
    has = [0] * n
    name = ''
    ip = ''
    for r in _merge_rows(_merge_map(), key, frm, end):
        m = (int(r['ts']) - frm) // 60
        if m < 0 or m >= n:
            continue
        has[m] = 1
        if r['present']:
            pres[m] = 1
            speed[m] += float(r['up'] or 0) + float(r['down'] or 0)
            sup[m] += float(r['up'] or 0)
            sdn[m] += float(r['down'] or 0)
            cnt[m] += 1
    for i in range(n):
        if cnt[i]:
            speed[i] = speed[i] / cnt[i]
            sup[i] = sup[i] / cnt[i]
            sdn[i] = sdn[i] / cnt[i]
    mkeys = _merge_keys(_merge_map(), key)
    for k in store.gw_keys(frm):
        if k['key'] in mkeys:
            name = k.get('name') or ''
            ip = k.get('ip') or ''
    name = _load_names().get(key, name)
    return jsonify(ok=True, key=key, name=name, ip=ip, frm=frm, now=now, end=end, minutes=n,
                   speed=speed, up=sup, down=sdn, present=pres, has=has)


@app.route('/api/gw/live', methods=['OPTIONS', 'GET'])
def api_gw_live():
    """分析页「实时」卡片：选定终端最近几分钟的逐条采样（上/下行分开）。

    新鲜度只看两个数：采样间隔（默认 10 秒）和上传间隔（默认 10 秒），
    所以最坏也就十几秒。这里把原始逐条采样直接回给前端，前端每 3 秒轮一次。
    """
    if request.method == 'OPTIONS':
        return _opt('GET, OPTIONS')
    if _auth_kind() is None:
        return _deny()
    key = (request.args.get('dev') or '').strip()
    if not key:
        return jsonify(ok=False, error='未指定设备'), 400
    try:
        secs = int(float(request.args.get('secs', 300)))
    except Exception:  # noqa: BLE001
        secs = 300
    secs = max(60, min(secs, 3600))
    now = int(time.time())
    try:
        rows = _merge_rows(_merge_map(), key, now - secs, now + 1)
    except Exception as e:  # noqa: BLE001
        return jsonify(ok=False, error='读取采样失败：%s' % str(e)[:120]), 500
    name = ''
    ip = ''
    try:
        for k in store.gw_keys(now - 7 * 86400):
            if k['key'] == key:
                name = k.get('name') or ''
                ip = k.get('ip') or ''
                break
    except Exception:  # noqa: BLE001
        pass
    name = _load_names().get(key, name)
    try:
        link = store.gw_last_link().get(key, '')
    except Exception:  # noqa: BLE001
        link = ''
    if link != 'wifi' and _wifi_only_default(name):
        link = 'wifi'
    link = _load_link_ov().get(key, link)
    samples = [[int(r['ts']), float(r['up'] or 0), float(r['down'] or 0),
                1 if r['present'] else 0] for r in rows]
    on = [s for s in samples if s[3]]
    last = samples[-1] if samples else None
    return jsonify(ok=True, now=now, key=key, name=name, ip=ip, link=link, win=secs,
                   n=len(samples), on_n=len(on),
                   ts=(last[0] if last else 0),
                   age=((now - last[0]) if last else -1),
                   present=(last[3] if last else 0),
                   up=(last[1] if last else 0.0), down=(last[2] if last else 0.0),
                   avg_up=(sum(s[1] for s in on) / len(on) if on else 0.0),
                   avg_down=(sum(s[2] for s in on) / len(on) if on else 0.0),
                   peak_up=(max(s[1] for s in on) if on else 0.0),
                   peak_down=(max(s[2] for s in on) if on else 0.0),
                   samples=samples)


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
