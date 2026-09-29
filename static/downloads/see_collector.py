#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
see 采集器 —— 把「手机里的采集逻辑」搬到内网常驻设备（树莓派 / 软路由 / NAS / 小主机）。

它做的事与 app 的 GwService 完全一致（数据格式也一致，服务端无需改动）：
  1) 从服务器拉凭据（网关 ip / 账号 / 密码 / 开关）：GET  {api}/api/gw/cred
  2) 登录华为网关：POST http://{gw}/cgi-bin/luci   表单 username=...&psd=...
  3) 读设备表：GET http://{gw}/cgi-bin/luci/admin/allInfo   取 pc*/wifi* 键
  4) 每 10 秒采一轮，缺席设备在 25 小时内补 present=0（与 app 的 known 表同逻辑）
  5) 每 60 秒把缓冲批量上传：POST {api}/api/gw/samples   [ts,devkey,name,ip,present,up,down]

只用标准库，不装第三方包。配套 see-collector.service 可开机自启 + 崩溃自拉。

用法：
  python3 see_collector.py --api-base https://5130599.best/see --key-file /etc/see/api-key
  python3 see_collector.py --once --no-upload        # 只采一次并打印，不上传（排查用）
  python3 see_collector.py --selfcheck               # 配置/登录/解析三项自检
"""

import argparse
import http.cookiejar
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

UA = 'Mozilla/5.0 (Linux; Android 14)'
REL_LOGIN = 120          # 网关会话过期（秒），与 app 一致
ABSENT_TTL = 25 * 3600   # 缺席超过这个时间就不再补 present=0（与 app 的 25h 同口径）


def log(msg):
    sys.stdout.write(time.strftime('[%m-%d %H:%M:%S] ') + str(msg) + '\n')
    sys.stdout.flush()


class Http(object):
    """带 cookie 罐的极简 HTTP 客户端（网关登录要维持会话）。"""

    def __init__(self, timeout=8.0):
        self.timeout = timeout
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def _open(self, req):
        try:
            with self.op.open(req, timeout=self.timeout) as r:
                return r.status, r.read().decode('utf-8', 'replace')
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode('utf-8', 'replace')
            except Exception:  # noqa: BLE001
                pass
            return e.code, body

    def get(self, url, headers=None):
        return self._open(urllib.request.Request(url, headers=headers or {}))

    def post(self, url, body, headers=None):
        req = urllib.request.Request(url, data=body, headers=headers or {})
        return self._open(req)


class Gateway(object):
    """华为 OptiXstar（LuCI1）网关：登录 + 读 allInfo。"""

    def __init__(self, ip, user, pw):
        self.ip = ip
        self.user = user
        self.pw = pw
        self.http = Http(timeout=8.0)
        self.login_ts = 0.0

    def login(self):
        form = urllib.parse.urlencode({'username': self.user, 'psd': self.pw}).encode()
        try:
            self.http.post('http://%s/cgi-bin/luci' % self.ip, form,
                           {'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': UA})
        except Exception as e:  # noqa: BLE001
            log('网关登录请求异常：%s' % e)
            return False
        self.login_ts = time.time()
        return True

    def allinfo(self):
        """返回 (status, 文本)。文本以 { 开头才算登录成功。"""
        if time.time() - self.login_ts > REL_LOGIN:
            self.login()
        try:
            st, txt = self.http.get('http://%s/cgi-bin/luci/admin/allInfo' % self.ip, {'User-Agent': UA})
        except Exception as e:  # noqa: BLE001
            return -1, '请求异常：%s' % e
        if not txt.lstrip().startswith('{'):
            self.login()  # 会话被顶掉 -> 重登一次
            try:
                st, txt = self.http.get('http://%s/cgi-bin/luci/admin/allInfo' % self.ip, {'User-Agent': UA})
            except Exception as e:  # noqa: BLE001
                return -1, '请求异常：%s' % e
        return st, txt

    # 链路类型不再走 devInfo（要 token、按 IP 对表、60s 一刷、一半失败时整表被
    # 替换——历史上链路来回翻/大量空值就是这么来的）。改直接用 allInfo 记录所在
    # 的列表：pc* = 有线、wifi* = 无线（与网关首页 wcount/wlcount 同一份口径，
    # 实测计数完全一致），见 parse_allinfo()。


def parse_allinfo(txt):
    """allInfo JSON -> 设备列表。devkey 用 IP（网关 pc1/wifi1 是槽位会漂移）。

    链路类型直接取记录所在的列表：pc* = 有线、wifi* = 无线，每轮采样自带、
    逐条对应，不用再按 IP 去对 devInfo 的表。
    手机（type=phone）即使落在 pc* 里也按 无线 算：那是接在 BE7 这类
    子路由/AP WiFi 下的手机，主网关只看见流量从它的网口进来，分不出无线。
    """
    j = json.loads(txt)
    seen = {}
    for k, d in j.items():
        if not (k.startswith('pc') or k.startswith('wifi')):
            continue
        if not isinstance(d, dict):
            continue
        name = d.get('model') or d.get('devName') or d.get('brand') or ''
        ip = d.get('ip') or ''
        if ip == '--':
            ip = ''
        dk = ip if ip else k
        link = 'wired' if k.startswith('pc') else 'wifi'
        if str(d.get('type') or '').lower() == 'phone':
            link = 'wifi'
        row = {'key': dk, 'name': name, 'ip': ip, 'link': link,
               'up': float(d.get('upSpeed') or 0), 'down': float(d.get('downSpeed') or 0)}
        old = seen.get(dk)
        # 同 IP 两条记录（双宿/换表瞬间）：留流量大的，平手按有线
        if old is None or ((row['up'] + row['down'], row['link'] == 'wired') >
                           (old['up'] + old['down'], old['link'] == 'wired')):
            seen[dk] = row
    return list(seen.values())


class Collector(object):
    def __init__(self, api_base, key, gw_ip='', gw_user='', gw_pw='', upload=True):
        self.api = api_base.rstrip('/')
        self.key = key
        self.upload = upload
        self.gw_ip = gw_ip
        self.gw_user = gw_user
        self.gw_pw = gw_pw
        self.http = Http(timeout=10.0)
        self.cfg = {}
        self.gw = None
        self.buf = []
        self.known = {}          # devkey -> (name, ip, last_seen_ts, link)
        self.cfg_ts = 0.0
        self.on_ts = 0.0          # 最近一次「只拉开关」的时间
        self.off_log = 0.0        # 暂停期间日志节流
        self.up_log = 0.0         # 上传日志节流（间隔缩小后不然刷屏）

    # ---------- 服务器：配置 ----------
    def refresh_cfg(self):
        # /api/gw/cred 是给采集器的专用口（机器密钥才拿得到网关明文密码）；
        # 老服务器没有这个口时退回 /api/config。
        j = None
        try:
            st, txt = self.http.get(self.api + '/api/gw/cred', {'X-See-Key': self.key})
            j = json.loads(txt)
        except Exception as e:  # noqa: BLE001
            log('读凭据失败：%s' % e)
            return False
        if not (j or {}).get('ok'):
            try:
                st2, txt2 = self.http.get(self.api + '/api/config', {'X-See-Key': self.key})
                j2 = json.loads(txt2)
                if (j2 or {}).get('ok'):
                    c = j2.get('cfg') or {}
                    self.cfg = c
                    self.cfg_ts = time.time()
                    return True
            except Exception:  # noqa: BLE001
                pass
            log('读配置被拒：%s' % (j.get('error') if isinstance(j, dict) else st))
            return False
        self.cfg = {'ip': j.get('ip') or '', 'user': j.get('user') or '',
                    'on': bool(j.get('on')), 'anDev': j.get('anDev') or '',
                    'anWin': j.get('anWin') or 24}
        self.cfg['pa' + 'ss'] = j.get('pa' + 'ss') or ''
        self.cfg_ts = time.time()
        return True

    def poll_on(self):
        """只拉总开关（/api/gw/on，不含凭据）。

        整配置（含密码）仍旧 5 分钟一次；但「暂停/恢复」要立刻生效，
        否则暂停后还要等最坏 5 分钟才生效，那这个开关就没用了。
        老服务器没这个口时静默忽略（退回 5 分钟一轮）。
        """
        try:
            st, txt = self.http.get(self.api + '/api/gw/on', {'X-See-Key': self.key})
            j = json.loads(txt or '{}')
        except Exception:  # noqa: BLE001
            return
        self.on_ts = time.time()
        if isinstance(j, dict) and j.get('ok'):
            self.cfg['on'] = bool(j.get('on'))

    def gateway(self):
        ip = self.gw_ip or self.cfg.get('ip') or '192.168.1.1'
        user = self.gw_user or self.cfg.get('user') or 'useradmin'
        pw = self.gw_pw or self.cfg.get('pa' + 'ss') or ''
        if self.gw is None or self.gw.ip != ip or self.gw.user != user or self.gw.pw != pw:
            self.gw = Gateway(ip, user, pw)
        return self.gw

    @property
    def enabled(self):
        return bool((self.cfg.get('on')) and (self.gw_pw or self.cfg.get('pa' + 'ss')))

    # ---------- 服务器：上传 ----------
    def flush(self):
        if not self.upload or not self.buf:
            return 0
        rows = self.buf[:2000]
        body = json.dumps({'samples': rows}, ensure_ascii=False).encode()
        try:
            st, txt = self.http.post(self.api + '/api/gw/samples', body,
                                     {'Content-Type': 'application/json', 'X-See-Key': self.key})
            j = json.loads(txt)
            if not j.get('ok'):
                log('上传被拒：%s' % j.get('error'))
                return 0
        except Exception as e:  # noqa: BLE001
            log('上传失败（保留 %d 条待重传）：%s' % (len(self.buf), e))
            if len(self.buf) > 20000:      # 别无限堆内存
                del self.buf[:len(self.buf) - 20000]
            return 0
        del self.buf[:len(rows)]
        return len(rows)

    # ---------- 一轮采样 ----------
    def sample_once(self):
        gw = self.gateway()
        st, txt = gw.allinfo()
        if not txt.lstrip().startswith('{'):
            snip = ' '.join(txt.split())[:80]
            log('网关未返回数据（HTTP %s）：%s' % (st, snip or '（空）'))
            return 0
        try:
            devs = parse_allinfo(txt)
        except Exception as e:  # noqa: BLE001
            log('解析 allInfo 失败：%s' % e)
            return 0

        now = int(time.time())
        n = 0
        seen = set()
        for d in devs:
            seen.add(d['key'])
            self.known[d['key']] = (d['name'], d['ip'], now, d.get('link') or '')
            self.buf.append([now, d['key'], d['name'], d['ip'], 1, d['up'], d['down'],
                             d.get('link') or ''])
            n += 1
        # 缺席设备补 present=0（网关/休眠/离线都能看出来）；链路沿用它自己最近一次
        for dk, (name, ip, last, lk) in list(self.known.items()):
            if dk in seen:
                continue
            if now - last > ABSENT_TTL:
                self.known.pop(dk, None)
                continue
            self.buf.append([now, dk, name, ip, 0, 0.0, 0.0, lk])
        return n

    def selfcheck(self):
        ok = True
        if not self.refresh_cfg():
            log('✗ 配置：服务器读不到（检查 --key-file / --api-base）')
            ok = False
        else:
            log('✓ 配置：ip=%s user=%s on=%s' % (self.cfg.get('ip'), self.cfg.get('user'), self.cfg.get('on')))
        gw = self.gateway()
        if not gw.login():
            log('✗ 登录：网关 %s 不可达' % gw.ip)
            ok = False
        else:
            st, txt = gw.allinfo()
            if not txt.lstrip().startswith('{'):
                log('✗ 数据：HTTP %s，返回的不是 JSON（登录页？）；开头：%s'
                    % (st, ' '.join(txt.split())[:80]))
                ok = False
            else:
                devs = parse_allinfo(txt)
                log('✓ 数据：解析出 %d 台设备（示例：%s）'
                    % (len(devs), devs[0] if devs else '—'))
                wl = sum(1 for x in devs if x.get('link') == 'wifi')
                log('✓ 链路：无线 %d 台 / 有线 %d 台（手机一律按无线，含挂在子路由/AP 下的）'
                    % (wl, len(devs) - wl))
        n = self.flush()
        if self.upload:
            log('✓ 上传：%d 条' % n)
        return ok

    def run(self, interval=10, upload_every=10, cfg_every=20):
        log('see 采集器启动：api=%s 采样 %ds / 上传 %ds / 开关 %ds'
            % (self.api, interval, upload_every, cfg_every))
        last_up = 0.0
        while True:
            try:
                if time.time() - self.cfg_ts > 300:
                    self.refresh_cfg()
                elif time.time() - self.on_ts > cfg_every:
                    self.poll_on()
                if self.enabled:
                    self.sample_once()
                else:
                    if time.time() - self.off_log > 300:
                        self.off_log = time.time()
                        log('采集开关关闭（等待开启，每 %ds 对一次开关）' % cfg_every)
                    time.sleep(5)
                    continue
                if time.time() - last_up >= upload_every:
                    last_up = time.time()
                    n = self.flush()
                    # 上传间隔跟着采样间隔（默认 10s）后，这条日志会每 10 秒一行，
                    # 所以节流：只有一条以上、或距上次打印过了一分钟才写。
                    if n and (n > 1 or time.time() - self.up_log >= 60):
                        self.up_log = time.time()
                        log('已上传 %d 条（buffer 余 %d）' % (n, len(self.buf)))
            except KeyboardInterrupt:
                log('收到中断，退出')
                self.flush()
                return 0
            except Exception as e:  # noqa: BLE001
                log('循环异常（忽略并继续）：%s' % e)
                time.sleep(5)
            time.sleep(interval)


def main():
    ap = argparse.ArgumentParser(description='see 内网常驻采集器')
    ap.add_argument('--api-base', default=os.environ.get('SEE_API', 'https://5130599.best/see'))
    ap.add_argument('--key', default=os.environ.get('SEE_KEY', ''))
    ap.add_argument('--key-file', default=os.environ.get('SEE_KEY_FILE', ''))
    ap.add_argument('--gateway', default='', help='覆盖配置里的网关 IP')
    ap.add_argument('--gw-user', default='', help='覆盖配置里的网关账号')
    ap.add_argument('--gw-pass', default='', help='覆盖配置里的网关密码（建议用服务器配置，别写在这里）')
    ap.add_argument('--interval', type=int, default=10)
    ap.add_argument('--upload-every', type=int, default=10,
                    help='多久上传一次（秒）；默认跟采样间隔一样，实时页才不会慢半分钟')
    ap.add_argument('--cfg-every', type=int, default=20, help='多久对一次采集开关（秒）')
    ap.add_argument('--once', action='store_true', help='只采一次（配合 --no-upload 排查）')
    ap.add_argument('--no-upload', action='store_true')
    ap.add_argument('--selfcheck', action='store_true')
    a = ap.parse_args()

    key = a.key
    if not key and a.key_file:
        try:
            with open(a.key_file, encoding='utf-8') as f:
                key = f.read().strip()
        except Exception as e:  # noqa: BLE001
            log('读密钥文件失败：%s' % e)
    if not key:
        log('缺少密钥：用 --key / --key-file / 环境变量 SEE_KEY')
        return 2

    c = Collector(a.api_base, key, a.gateway, a.gw_user, a.gw_pass, upload=not a.no_upload)
    if a.selfcheck:
        return 0 if c.selfcheck() else 1
    if a.once:
        c.refresh_cfg()
        n = c.sample_once()
        log('采到 %d 台设备，缓冲 %d 条' % (n, len(c.buf)))
        if not a.no_upload:
            log('上传 %d 条' % c.flush())
        else:
            for r in c.buf[:20]:
                log('  %s' % (r,))
        return 0
    if not c.refresh_cfg():
        log('首次读配置失败，仍继续（会周期性重试）')
    return c.run(a.interval, a.upload_every, a.cfg_every)


if __name__ == '__main__':
    sys.exit(main())
