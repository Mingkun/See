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

    private fun ipToLong(ip: String): Long =
        ip.split('.').fold(0L) { a, b -> (a shl 8) or (b.toLongOrNull() ?: 0) }

    private fun longToIp(v: Long): String =
        "${(v shr 24) and 255}.${(v shr 16) and 255}.${(v shr 8) and 255}.${v and 255}"

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
            pool.execute { if (ping(ip)) alive.add(ip) }
        }
        pool.shutdown()
        try { pool.awaitTermination(25, TimeUnit.SECONDS) } catch (_: Exception) {}
        val arp = readArp()
        val found = LinkedHashMap<String, String>()
        for ((ip, mac) in arp) found[ip] = mac
        for (ip in alive) if (!found.containsKey(ip)) found[ip] = "ip:$ip"
        merge(found)
        probeTypes()
        lastSweep = System.currentTimeMillis() / 1000
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
            for ((mac, d) in devices) {
                if (d.online && now - d.lastSeen > 30) {
                    d.online = false
                    addEventLocked("offline", d.ip, mac, d.hostname)
                }
            }
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

    private fun vendor(mac: String): String = try {
        val conn = URL("https://api.macvendors.com/$mac").openConnection() as HttpURLConnection
        conn.connectTimeout = 4000; conn.readTimeout = 4000
        val v = conn.inputStream.readBytes().toString(Charsets.UTF_8).trim()
        Thread.sleep(1200)
        v.take(32)
    } catch (_: Exception) { "" }
}
