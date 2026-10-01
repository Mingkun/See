# coding: utf-8
"""ARP sweep scanner: discover LAN devices, emit join/offline events."""
import ipaddress
import socket
import subprocess
import threading
import time
import urllib.request

from scapy.all import ARP, Ether, srp

UA = {'User-Agent': 'see-monitor/1.0'}


class Scanner(threading.Thread):
    def __init__(self, store, cidr, iface, interval=10, offline_after=30, scan_mode='auto'):
        super().__init__(daemon=True)
        self.store = store
        self.cidr = cidr
        self.iface = iface
        self.scan_mode = scan_mode  # auto | arp | ping
        self.interval = interval
        self.offline_after = offline_after
        self.seen = {}  # mac -> {ip, hostname, vendor, last_seen, online}
        self.external_ts = 0.0   # 采集器上报时间：近 120s 内有上报就不本机扫
        self.known_macs = set()  # macs recorded before startup (no re-join spam)
        self.lock = threading.Lock()
        self.last_sweep = 0
        self.last_error = ''

    def prime_known(self):
        for d in self.store.all_devices():
            self.known_macs.add(d['mac'])
            self.seen[d['mac']] = {'ip': d['ip'], 'hostname': d.get('hostname') or '',
                                   'vendor': d.get('vendor') or '', 'last_seen': 0, 'online': False}

    # ---------- helpers ----------
    def sweep(self):
        mode = self.scan_mode
        if mode in ('arp', 'auto'):
            try:
                out = self._sweep_arp()
                if mode == 'auto':
                    self.scan_mode = 'arp'
                return out
            except PermissionError:
                if mode == 'arp':
                    return {}
                self.scan_mode = 'ping'
            except Exception as exc:  # noqa: BLE001
                self.last_error = str(exc)[:120]
                if mode == 'arp':
                    return {}
                self.scan_mode = 'ping'
        try:
            return self._sweep_ping()
        except Exception as exc:  # noqa: BLE001
            self.last_error = str(exc)[:120]
            return {}

    def _sweep_arp(self):
        ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=self.cidr),
                     timeout=2, iface=self.iface, verbose=0, inter=0.001)
        out = {}
        for _, rcv in ans:
            mac = rcv[ARP].hwsrc
            ip = rcv[ARP].psrc
            if mac and mac not in ('00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff'):
                out[ip] = mac
        return out

    def _sweep_ping(self):
        """免 root 回退：并发 ping 全网段后读 /proc/net/arp（手机 Termux 可用）。"""
        import concurrent.futures
        import os
        devnull = subprocess.DEVNULL
        hosts = [str(h) for h in ipaddress.ip_network(self.cidr).hosts()]

        def ping(ip):
            try:
                subprocess.run(['ping', '-c', '1', '-W', '1', '-n', ip],
                               stdout=devnull, stderr=devnull, timeout=3)
            except Exception:  # noqa: BLE001
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
            list(ex.map(ping, hosts))
        out = {}
        try:
            for line in open('/proc/net/arp', encoding='utf-8', errors='ignore').read().splitlines()[1:]:
                f = line.split()
                if len(f) >= 4 and f[2] == '0x2':
                    ip, hw = f[0], f[3]
                    if hw and hw != '00:00:00:00:00:00' and os.path.exists('/proc/net/arp'):
                        out[ip] = hw
        except Exception:  # noqa: BLE001
            pass
        return out

    def hostname_for(self, ip, cached):
        if cached:
            return cached
        try:
            return socket.sethostbyaddr(ip)[0] if False else socket.gethostbyaddr(ip)[0]
        except Exception:
            return ''

    def vendor_for(self, mac, cached):
        if cached:
            return cached
        try:
            req = urllib.request.Request('https://api.macvendors.com/' + mac, headers=UA)
            v = urllib.request.urlopen(req, timeout=4).read().decode('utf-8', 'ignore').strip()
            time.sleep(1.2)  # free API rate limit
            return v[:32]
        except Exception:
            return ''

    # ---------- main loop ----------
    def apply_report(self, rows):
        """采集器上报的局域网发现结果（ip/mac/vendor）→ 喂进 seen 并记 join/online/offline 事件。
        外部源生效期间（120s 内有上报）run() 不再本机扫。"""
        now = time.time()
        with self.lock:
            self.external_ts = now
            for r in rows:
                mac = str(r.get('mac') or '').upper()
                ip = str(r.get('ip') or '').strip()
                if not mac or not ip or mac == '00:00:00:00:00:00':
                    continue
                st = self.seen.get(mac)
                if st is None:
                    hostname = str(r.get('hostname') or '')
                    vendor = str(r.get('vendor') or '')
                    st = {'ip': ip, 'hostname': hostname, 'vendor': vendor,
                          'type': str(r.get('type') or ''), 'last_seen': now, 'online': True}
                    self.seen[mac] = st
                    self.store.upsert_device(mac, ip, hostname or None, vendor or None, int(now))
                    if mac not in self.known_macs:
                        self.known_macs.add(mac)
                        self.store.add_event('join', ip, mac, hostname)
                else:
                    was_offline = not st['online']
                    st['ip'] = ip
                    if r.get('hostname'):
                        st['hostname'] = str(r['hostname'])
                    if r.get('vendor'):
                        st['vendor'] = str(r['vendor'])
                    if r.get('type'):
                        st['type'] = str(r['type'])
                    st['last_seen'] = now
                    st['online'] = True
                    self.store.upsert_device(mac, ip, st['hostname'] or None, st['vendor'] or None, int(now))
                    if was_offline:
                        self.store.add_event('online', ip, mac, st['hostname'])
            for mac, st in self.seen.items():
                if st['online'] and st['last_seen'] and now - st['last_seen'] > 180:
                    st['online'] = False
                    self.store.add_event('offline', st['ip'], mac, st['hostname'])
        return len(self.seen)

    def run(self):
        while True:
            if time.time() - self.external_ts < 120:
                time.sleep(self.interval)   # 采集器在喂数据，本机不扫（云服务器上也扫不到家里）
                continue
            found = self.sweep()
            now = time.time()
            self.last_sweep = int(now)
            with self.lock:
                for ip, mac in found.items():
                    st = self.seen.get(mac)
                    if st is None:
                        hostname = self.hostname_for(ip, '')
                        vendor = self.vendor_for(mac, '')
                        st = {'ip': ip, 'hostname': hostname, 'vendor': vendor,
                              'last_seen': now, 'online': True}
                        self.seen[mac] = st
                        self.store.upsert_device(mac, ip, hostname, vendor, int(now))
                        if mac not in self.known_macs:
                            self.known_macs.add(mac)
                            self.store.add_event('join', ip, mac, hostname)
                    else:
                        was_offline = not st['online']
                        st['ip'] = ip
                        st['last_seen'] = now
                        st['online'] = True
                        self.store.upsert_device(mac, ip, st['hostname'] or None, st['vendor'] or None, int(now))
                        if was_offline and st['last_seen']:
                            self.store.add_event('online', ip, mac, st['hostname'])
                for mac, st in self.seen.items():
                    if st['online'] and st['last_seen'] and now - st['last_seen'] > self.offline_after:
                        st['online'] = False
                        self.store.add_event('offline', st['ip'], mac, st['hostname'])
            time.sleep(self.interval)

    # ---------- views ----------
    def devices(self):
        with self.lock:
            out = []
            for mac, st in self.seen.items():
                out.append({'mac': mac, 'ip': st['ip'], 'hostname': st['hostname'],
                            'vendor': st['vendor'], 'type': st.get('type', ''),
                            'online': st['online'], 'last_seen': st['last_seen']})
            return out

    def local_ips(self):
        with self.lock:
            return {st['ip'] for _, st in self.seen.items() if st['ip']}
