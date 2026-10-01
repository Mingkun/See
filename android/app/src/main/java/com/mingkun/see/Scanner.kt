package com.mingkun.see

import java.io.File
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

class Scanner(private val db: Db) : Thread() {

    data class Dev(var ip: String, var hostname: String, var vendor: String, var lastSeen: Long, var online: Boolean, var type: String = "")
    data class Ev(val ts: Long, val type: String, val ip: String, val mac: String, val hostname: String)

    @Volatile var subnet: String = ""   // 192.168.1.0/24
    @Volatile var gateway: String = ""
    @Volatile var selfIp: String = ""
    val devices = LinkedHashMap<String, Dev>()
    val events = mutableListOf<Ev>()
    val lock = Any()
    private val knownMacs = mutableSetOf<String>()
    @Volatile var lastSweep = 0L
    @Volatile var lastError = ""
    val startTs = System.currentTimeMillis() / 1000

    override fun run() {
        for (d in db.devices()) {
            knownMacs.add(d[0])
            synchronized(lock) { devices[d[0]] = Dev(d[1], d[2] ?: "", d[3] ?: "", 0, false) }
        }
        while (!isInterrupted) {
            try {
                if (subnet.isNotBlank()) { sweep(); lastError = "" }
                else lastError = "未获取到网段（请连接WiFi）"
            } catch (e: Exception) {
                lastError = (e.message ?: "err").take(120)
            }
            try { synchronized(wakeLock) { wakeLock.wait(10_000) } } catch (_: InterruptedException) { return }
        }
    }

    private val wakeLock = Object()
    fun scanNow() { synchronized(wakeLock) { wakeLock.notifyAll() } }

    /** 点「立即扫描」时先把观察页的历史清掉：设备列表 + 动态事件（含本地库），再重新扫。 */
    fun resetHistory() {
        synchronized(lock) {
            events.clear()
            devices.clear()
        }
        db.clearHistory()
    }

    private fun ipToLong(ip: String): Long =
        ip.split('.').fold(0L) { a, b -> (a shl 8) or (b.toLongOrNull() ?: 0) }

    private fun longToIp(v: Long): String =
        "${(v shr 24) and 255}.${(v shr 16) and 255}.${(v shr 8) and 255}.${v and 255}"

    /** 某个 ip 是否落在本机所在网段（观察页只管手机自己的这一层局域网） */
    private fun inSubnet(ip: String, cidr: String): Boolean {
        if (cidr.isBlank()) return false
        val prefix = cidr.substringAfterLast('/').toIntOrNull() ?: 24
        val hostBits = 32 - prefix
        val mask = (-1L shl hostBits) and 0xFFFFFFFFL
        val base = ipToLong(cidr.substringBefore('/')) and mask
        return (ipToLong(ip) and mask) == base
    }

    private fun sweep() {
        val prefix = subnet.substringAfterLast('/').toIntOrNull() ?: 24
        val hostBits = 32 - prefix
        val mask = (-1L shl hostBits) and 0xFFFFFFFFL
        val base = ipToLong(subnet.substringBefore('/')) and mask
        val count = minOf((1L shl hostBits) - 2, 510)
        val alive = java.util.Collections.synchronizedSet(HashSet<String>())
        val pool = Executors.newFixedThreadPool(64)
        for (i in 1..count) {
            val ip = longToIp(base + i)
            pool.execute { udpPoke(ip); if (ping(ip)) alive.add(ip) }
        }
        pool.shutdown()
        try { pool.awaitTermination(25, TimeUnit.SECONDS) } catch (_: Exception) {}
        val arp = readArp()
        val found = LinkedHashMap<String, String>()
        for ((ip, mac) in arp) found[ip] = mac
        for (ip in alive) if (!found.containsKey(ip)) found[ip] = "ip:$ip"
        ssdpScan()
        mdnsScan()
        merge(found)
        probeTypes()
        lastSweep = System.currentTimeMillis() / 1000
    }

    /** SSDP/UPnP：M-SEARCH 组播 → 拉 XML → 设备自述（friendlyName/manufacturer/modelName） */
    private fun ssdpScan() {
        try {
            val socket = java.net.DatagramSocket()
            socket.soTimeout = 500
            socket.reuseAddress = true
            val msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n" +
                "MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n").toByteArray()
            socket.send(java.net.DatagramPacket(msg, msg.size,
                java.net.InetAddress.getByName("239.255.255.250"), 1900))
            val locations = mutableMapOf<String, String>()
            val end = System.currentTimeMillis() + 3000
            while (System.currentTimeMillis() < end) {
                try {
                    val buf = ByteArray(4096)
                    val pkt = java.net.DatagramPacket(buf, buf.size)
                    socket.receive(pkt)
                    val txt = String(pkt.data, 0, pkt.length, Charsets.UTF_8)
                    val loc = Regex("""LOCATION:\s*(.+)""", RegexOption.IGNORE_CASE)
                        .find(txt)?.groupValues?.get(1)?.trim() ?: continue
                    locations[pkt.address.hostAddress ?: continue] = loc
                } catch (_: java.net.SocketTimeoutException) { break }
            }
            socket.close()
            for ((ip, url) in locations.entries.take(15)) {
                try {
                    val conn = java.net.URL(url).openConnection() as java.net.HttpURLConnection
                    conn.connectTimeout = 3000; conn.readTimeout = 3000
                    val xml = conn.inputStream.readBytes().toString(Charsets.UTF_8)
                    val fn = Regex("<friendlyName>(.*?)</friendlyName>", RegexOption.DOT_MATCHES_ALL).find(xml)?.groupValues?.get(1)?.trim() ?: ""
                    val mf = Regex("<manufacturer>(.*?)</manufacturer>", RegexOption.DOT_MATCHES_ALL).find(xml)?.groupValues?.get(1)?.trim() ?: ""
                    val md = Regex("<modelName>(.*?)</modelName>", RegexOption.DOT_MATCHES_ALL).find(xml)?.groupValues?.get(1)?.trim() ?: ""
                    synchronized(lock) {
                        for ((_, d) in devices) {
                            if (d.ip == ip) {
                                if (fn.isNotEmpty() && d.hostname.isEmpty()) d.hostname = fn.take(24)
                                if (mf.isNotEmpty() && d.vendor.isEmpty()) d.vendor = mf.take(24)
                                if (md.isNotEmpty() && d.type.isEmpty()) d.type = md.take(24)
                                db.upsert(macOf(d.ip) ?: "", ip, d.hostname, d.vendor, System.currentTimeMillis() / 1000)
                            }
                        }
                    }
                } catch (_: Exception) {}
            }
        } catch (_: Exception) {}
    }

    /** mDNS：DNS-SD PTR 查询 → 抓 _xxx._tcp/_udp 服务名 → type */
    private fun mdnsScan() {
        try {
            val query = byteArrayOf(0,0,1,0,0,1,0,0,0,0,0,0) +
                "_services".toByteArray() + byteArrayOf(7) + "_dns-sd".toByteArray() +
                byteArrayOf(7) + "_udp".toByteArray() + byteArrayOf(5) + "local".toByteArray() +
                byteArrayOf(0,0,12,0,1)
            val socket = java.net.DatagramSocket()
            socket.soTimeout = 500
            socket.send(java.net.DatagramPacket(query, query.size,
                java.net.InetAddress.getByName("224.0.0.251"), 5353))
            val svc = mutableMapOf<String, MutableSet<String>>()
            val end = System.currentTimeMillis() + 2500
            while (System.currentTimeMillis() < end) {
                try {
                    val buf = ByteArray(4096)
                    val pkt = java.net.DatagramPacket(buf, buf.size)
                    socket.receive(pkt)
                    val raw = String(pkt.data, 0, pkt.length, Charsets.ISO_8859_1)
                    val names = Regex("""_[a-zA-Z0-9-]{2,32}\._[a-zA-Z0-9-]{2,16}\._(?:tcp|udp)""")
                        .findAll(raw).map { it.value }.toSet()
                    if (names.isNotEmpty()) {
                        val ip = pkt.address.hostAddress ?: continue
                        svc.getOrPut(ip) { mutableSetOf() }.addAll(names)
                    }
                } catch (_: java.net.SocketTimeoutException) { break }
            }
            socket.close()
            synchronized(lock) {
                for ((ip, svcs) in svc) {
                    for ((_, d) in devices) {
                        if (d.ip == ip && d.type.isEmpty() && svcs.isNotEmpty()) {
                            d.type = svcs.joinToString("·").take(24)
                        }
                    }
                }
            }
        } catch (_: Exception) {}
    }

    private fun macOf(ip: String): String? {
        synchronized(lock) { for ((mac, d) in devices) if (d.ip == ip) return mac }
        return null
    }

    private val probePorts = listOf(
        62078 to "📱 iPhone/iPad", 8000 to "📷 海康摄像头", 37777 to "📷 大华摄像头", 554 to "📷 摄像头",
        9100 to "🖨 打印机", 631 to "🖨 打印机", 5000 to "🗄 NAS", 5001 to "🗄 NAS",
        3000 to "📺 LG电视", 3001 to "📺 LG电视", 2179 to "📺 Chromecast", 8009 to "📺 Chromecast",
        548 to "💻 Mac", 3689 to "💻 Mac", 445 to "💻 Windows", 139 to "💻 Windows", 3389 to "💻 Windows",
        5555 to "📱 Android"
    )

    private fun probeTypes() {
        val targets = synchronized(lock) {
            devices.entries.filter { it.value.online && it.value.type.isEmpty() }
                .map { it.key to it.value.ip }
        }
        if (targets.isEmpty()) return
        val pool = Executors.newFixedThreadPool(12)
        for ((key, ip) in targets) pool.execute {
            val t = probeIp(ip)
            if (t.isNotEmpty()) synchronized(lock) { devices[key]?.type = t }
        }
        pool.shutdown()
        try { pool.awaitTermination(10, TimeUnit.SECONDS) } catch (_: Exception) {}
    }

    private fun probeIp(ip: String): String {
        val hits = java.util.Collections.synchronizedList(mutableListOf<Int>())
        val sub = Executors.newFixedThreadPool(probePorts.size)
        probePorts.forEachIndexed { i, pp ->
            sub.execute {
                try {
                    val s = java.net.Socket()
                    s.connect(java.net.InetSocketAddress(ip, pp.first), 400)
                    s.close()
                    hits.add(i)
                } catch (_: Exception) {}
            }
        }
        sub.shutdown()
        try { sub.awaitTermination(2, TimeUnit.SECONDS) } catch (_: Exception) {}
        return hits.minOrNull()?.let { probePorts[it].second } ?: ""
    }

    private fun ping(ip: String): Boolean = try {
        val p = ProcessBuilder("/system/bin/ping", "-c", "1", "-W", "1", "-n", ip)
            .redirectErrorStream(true).start()
        val ok = p.waitFor() == 0
        p.destroy()
        ok
    } catch (_: Exception) { false }

    private fun readArp(): Map<String, String> {
        // 注意：/proc/net/arp 是**本机所有接口共用**的一张表，不限于 WiFi。
        // 只要有过通信，VPN / 容器 / 热点等接口的地址也会出现在里面
        // （实测用户在 192.168.1.x 的网里被扫出 172.19.0.2）。
        // 过滤统一在 merge() 里按本机网段做（单一的漏斗），不在这里重复。
        val out = mutableMapOf<String, String>()
        try {
            val lines = File("/proc/net/arp").readText().split('\n')
            for ((idx, l) in lines.withIndex()) {
                if (idx == 0 || l.isBlank()) continue
                val f = l.trim().split(Regex("\\s+"))
                if (f.size >= 4 && f[2] == "0x2" && f[3].contains(':')) out[f[0]] = f[3]
            }
        } catch (_: Exception) {}
        return out
    }

    private fun merge(found: Map<String, String>) {
        val now = System.currentTimeMillis() / 1000
        synchronized(lock) {
            for ((ip, mac) in found) {
                if (mac == "00:00:00:00:00:00") continue
                // 只认本机所在网段：ARP 表跨接口，VPN/容器会把别的网段带进来
                if (subnet.isNotBlank() && !inSubnet(ip, subnet)) continue
                val d = devices[mac]
                if (d == null) {
                    devices[mac] = Dev(ip, "", "", now, true)
                    db.upsert(mac, ip, "", "", now)
                    val hasMac = mac.length == 17 && !mac.startsWith("ip:")
                    thread {
                        val h = hostname(ip)
                        val v = if (hasMac) vendor(mac) else ""
                        synchronized(lock) {
                            devices[mac]?.let { it.hostname = h; it.vendor = v }
                            val dv = devices[mac]
                            if (h.startsWith("android-", true) && (dv?.type ?: "").isEmpty()) dv?.type = "📱 Android"
                        }
                        db.upsert(mac, ip, h, v, now)
                    }
                    if (mac !in knownMacs) {
                        knownMacs.add(mac)
                        addEventLocked("join", ip, if (hasMac) mac else "", "")
                    }
                } else {
                    val wasOffline = !d.online
                    d.ip = ip; d.lastSeen = now; d.online = true
                    db.upsert(mac, ip, d.hostname, d.vendor, now)
                    if (wasOffline && d.lastSeen > 0) addEventLocked("online", ip, mac, d.hostname)
                }
                devices[mac]?.let { dv ->
                    if (dv.type.isEmpty()) {
                        if (gateway.isNotEmpty() && ip == gateway) dv.type = "🌐 路由器"
                        else if (selfIp.isNotEmpty() && ip == selfIp) dv.type = "📱 本机"
                    }
                }
            }
            val foreign = mutableListOf<String>()
            for ((mac, d) in devices) {
                // 已经混进来的外网段设备（历史数据）直接清掉，不留残留
                if (subnet.isNotBlank() && d.ip.isNotEmpty() && !inSubnet(d.ip, subnet)) {
                    foreign.add(mac); continue
                }
                if (d.online && now - d.lastSeen > 30) {
                    d.online = false
                    addEventLocked("offline", d.ip, mac, d.hostname)
                }
            }
            for (k in foreign) { devices.remove(k); knownMacs.remove(k); db.deleteDevice(k) }
        }
    }

    private fun addEventLocked(type: String, ip: String, mac: String, hostname: String) {
        val e = Ev(System.currentTimeMillis() / 1000, type, ip, mac, hostname)
        events.add(0, e)
        if (events.size > 200) events.removeAt(events.size - 1)
        db.addEvent(e.ts, type, ip, mac, hostname)
    }

    private fun hostname(ip: String): String = try {
        InetAddress.getByName(ip).canonicalHostName.takeIf { it != ip } ?: ""
    } catch (_: Exception) { "" }

    /** 快速 UDP 探测（发到 discard 端口 9）：不回 ping 的设备也能把 ARP 表刷出来 */
    private fun udpPoke(ip: String) {
        try {
            val s = java.net.DatagramSocket()
            s.soTimeout = 150
            val addr = java.net.InetAddress.getByName(ip)
            s.send(java.net.DatagramPacket(ByteArray(0), 0, addr, 9))
            s.close()
        } catch (_: Exception) {}
    }

    /** 常见厂商 OUI（本地表，秒回、离线可用）；认不出的再试外网 macvendors */
    private val localOui = mapOf(
        "246F28" to "乐鑫Espressif", "30AEA4" to "乐鑫Espressif", "5CCF7F" to "乐鑫Espressif",
        "A4CF12" to "乐鑫Espressif", "BCDDC2" to "乐鑫Espressif", "68C63A" to "乐鑫Espressif",
        "24B2DE" to "乐鑫Espressif", "183AF0" to "乐鑫Espressif", "D8A01B" to "乐鑫Espressif",
        "640980" to "小米", "7811DC" to "小米", "ACC1EE" to "小米", "508F4C" to "小米", "F8A45F" to "小米",
        "ECA62F" to "华为"
    )

    private fun vendor(mac: String): String {
        val local = localOui[mac.replace(":", "").uppercase().take(6)]
        if (local != null) return local
        return try {
        val conn = URL("https://api.macvendors.com/$mac").openConnection() as HttpURLConnection
        conn.connectTimeout = 4000; conn.readTimeout = 4000
        val v = conn.inputStream.readBytes().toString(Charsets.UTF_8).trim()
            Thread.sleep(1200)
            v.take(32)
        } catch (_: Exception) { "" }
    }
}
