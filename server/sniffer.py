# coding: utf-8
"""Gateway-mode traffic monitor: per-device up/down counters, speeds, flows, DNS/SNI maps."""
import collections
import re
import threading
import time

from scapy.all import IP, Raw, TCP, sniff

SNI_RE = re.compile(rb'[a-z0-9][a-z0-9\-\._]{3,60}\.[a-z]{2,6}', re.I)
IP_RE = re.compile(r'^\d+\.\d+\.\d+\.\d+$')
FLOW_TTL = 600


class TrafficMonitor(threading.Thread):
    def __init__(self, iface, local_ip_getter, enabled=True):
        super().__init__(daemon=True)
        self.iface = iface
        self.enabled = enabled
        self.get_local_ips = local_ip_getter
        self.up = collections.defaultdict(int)
        self.down = collections.defaultdict(int)
        self.hist = {}   # ip -> [(ts, up, down)] max 8
        self.speed = {}  # ip -> {'up','down'} bytes/s
        self.flows = {}  # (ip, remote, port, proto) -> {'up','down','ts'}
        self.dns_map = {}  # remote ip -> domain
        self.sni_map = {}  # remote ip -> sni
        self.lock = threading.Lock()
        self.pkt_count = 0

    # ---------- packet handling ----------
    def _on_pkt(self, pkt):
        if IP not in pkt:
            return
        ip = pkt[IP]
        size = len(ip)
        self.pkt_count += 1
        s, d = ip.src, ip.dst
        if pkt.haslayer('DNS') and pkt['DNS'].qr:
            try:
                self._dns(pkt['DNS'])
            except Exception:
                pass
        if TCP in pkt and pkt[TCP].dport == 443 and Raw in pkt:
            try:
                payload = bytes(pkt[Raw])
                if payload and payload[0] == 0x16:
                    m = SNI_RE.findall(payload)
                    if m:
                        sni = m[-1].decode('utf-8', 'ignore').lower().strip('.')
                        with self.lock:
                            self.sni_map[d] = sni
                        if len(self.sni_map) > 4000:
                            with self.lock:
                                self.sni_map.clear()
            except Exception:
                pass
        local = self.get_local_ips()
        if not local:
            return
        sport = pkt[TCP].sport if TCP in pkt else (pkt['UDP'].sport if pkt.haslayer('UDP') else None)
        dport = pkt[TCP].dport if TCP in pkt else (pkt['UDP'].dport if pkt.haslayer('UDP') else None)
        proto = 'tcp' if TCP in pkt else ('udp' if pkt.haslayer('UDP') else 'ip')
        with self.lock:
            if s in local and d not in local:
                self.up[s] += size
                self._flow(s, d, dport, proto, 'up', size)
            elif d in local and s not in local:
                self.down[d] += size
                self._flow(d, s, sport, proto, 'down', size)

    def _dns(self, dns):
        qname = ''
        try:
            qname = (dns.qd.qname or b'').decode('utf-8', 'ignore').rstrip('.')
        except Exception:
            return
        if not qname:
            return
        now = time.time()
        with self.lock:
            for i in range(min(dns.ancount or 0, 30)):
                try:
                    an = dns.an[i]
                except Exception:
                    break
                rr = getattr(an, 'rdata', None)
                if rr is None:
                    continue
                if hasattr(rr, 'decode'):
                    try:
                        rr = rr.decode('utf-8', 'ignore')
                    except Exception:
                        continue
                if isinstance(rr, str) and IP_RE.match(rr):
                    self.dns_map[rr] = qname
            if len(self.dns_map) > 8000:
                self.dns_map.clear()

    def _flow(self, lip, rip, port, proto, direction, size):
        key = (lip, rip, port, proto)
        f = self.flows.get(key)
        if f is None:
            f = self.flows[key] = {'up': 0, 'down': 0, 'ts': time.time()}
        f[direction] += size
        f['ts'] = time.time()
        if len(self.flows) > 6000:
            cutoff = time.time() - FLOW_TTL
            self.flows = {k: v for k, v in self.flows.items() if v['ts'] >= cutoff}

    # ---------- thread ----------
    def run(self):
        if not self.enabled:
            return
        try:
            sniff(iface=self.iface, filter='ip', prn=self._on_pkt, store=False)
        except Exception as exc:  # noqa: BLE001
            self.enabled = False
            self.error = str(exc)[:200]

    # ---------- ticker (called from app loop) ----------
    def tick(self):
        now = time.time()
        with self.lock:
            for ip in set(self.up) | set(self.down):
                h = self.hist.setdefault(ip, [])
                h.append((now, self.up[ip], self.down[ip]))
                if len(h) > 8:
                    del h[:len(h) - 8]
                if len(h) >= 2:
                    t0, u0, d0 = h[0]
                    dt = max(now - t0, 0.5)
                    self.speed[ip] = {'up': (self.up[ip] - u0) / dt,
                                      'down': (self.down[ip] - d0) / dt}
                else:
                    self.speed[ip] = {'up': 0, 'down': 0}

    # ---------- views ----------
    def speeds(self, ip):
        with self.lock:
            sp = self.speed.get(ip)
            return {'up': sp['up'] if sp else 0, 'down': sp['down'] if sp else 0}

    def totals(self, ip):
        with self.lock:
            return {'up': self.up.get(ip, 0), 'down': self.down.get(ip, 0)}

    def apps(self, ip, minutes=5, top=8):
        from applist import app_label
        cutoff = time.time() - minutes * 60
        out = {}
        with self.lock:
            for (lip, rip, port, proto), v in self.flows.items():
                if lip != ip or v['ts'] < cutoff:
                    continue
                label = app_label(rip, port, proto, self.dns_map, self.sni_map)
                a = out.setdefault(label, [0, 0])
                a[0] += v['up']
                a[1] += v['down']
        items = sorted(({'app': k, 'up': v[0], 'down': v[1]} for k, v in out.items()),
                       key=lambda x: -(x['up'] + x['down']))
        return items[:top]
