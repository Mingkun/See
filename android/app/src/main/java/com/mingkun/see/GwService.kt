package com.mingkun.see

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

/**
 * 常驻前台服务：即使 app 界面被关闭/切到后台，也持续轮询网关设备表，
 * 把每台设备的在线状态与实时速率采样上传到服务器，供分析页随时查看。
 *
 * 前提：手机必须开机、连着家里 WiFi（服务器在公网，访问不到内网网关）。
 */
class GwService : Service() {
    companion object {
        const val CFG_URL = "https://5130599.best/see/api/config"
        const val SAMPLES_URL = "https://5130599.best/see/api/gw/samples"
        const val SEE_KEY = "e3d6bf27b00815b9aca0a5933cefbed1"
        private const val CH = "see_bg"
        private const val NID = 4001

        @Volatile var running = false
            private set

        fun start(ctx: Context) {
            val i = Intent(ctx, GwService::class.java)
            if (Build.VERSION.SDK_INT >= 26) ctx.startForegroundService(i) else ctx.startService(i)
        }

        fun stop(ctx: Context) {
            running = false
            ctx.stopService(Intent(ctx, GwService::class.java))
        }
    }

    @Volatile private var cfgIp = "192.168.1.1"
    @Volatile private var cfgUser = "useradmin"
    @Volatile private var cfgPw = ""
    private var loginTs = 0L
    private var loginIp = ""
    private var lastCfgTs = 0L
    private val buf = ArrayList<Array<Any>>()
    private var lastUpTs = 0L
    private var lastPruneHint = 0L

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        running = true
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForegroundSafe()
        running = true
        Thread {
            try {
                loop()
            } catch (e: Exception) {
                // 出错也不崩服务
            }
            running = false
            try { stopForeground(true) } catch (_: Exception) {}
            stopSelf()
        }.start()
        return START_STICKY
    }

    private fun startForegroundSafe() {
        try {
            val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
            if (Build.VERSION.SDK_INT >= 26) {
                nm.createNotificationChannel(
                    NotificationChannel(CH, "see 后台采集", NotificationManager.IMPORTANCE_LOW))
            }
            val open = PendingIntent.getActivity(this, 9,
                Intent(this, MainActivity::class.java),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            val stop = PendingIntent.getService(this, 10,
                Intent(this, GwService::class.java).setAction("stop"),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            var nb = Notification.Builder(this, CH)
                .setSmallIcon(android.R.drawable.stat_notify_sync)
                .setContentTitle("see 后台采集中")
                .setContentText("持续记录网关设备流量，供分析页查看")
                .setContentIntent(open)
                .setOngoing(true)
            try { nb = nb.addAction(Notification.Action.Builder(null, "停止", stop).build()) } catch (_: Exception) {}
            val n: Notification = nb.build()
            if (Build.VERSION.SDK_INT >= 29) {
                startForeground(NID, n, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
            } else {
                startForeground(NID, n)
            }
        } catch (e: Exception) {
        }
    }

    override fun onDestroy() {
        running = false
        super.onDestroy()
    }

    private fun loop() {
        var lastSample = 0L
        while (running) {
            try {
                val now = System.currentTimeMillis() / 1000
                if (now - lastCfgTs > 300) {
                    lastCfgTs = now
                    if (!refreshCfg()) {
                        sleepMs(15000)
                        continue
                    }
                }
                if (now - lastSample >= 10) {
                    lastSample = now
                    val arr = fetchDevices()
                    if (arr != null) {
                        record(now, arr)
                    }
                }
                if (buf.size > 0 && now - lastUpTs >= 60) {
                    upload()
                }
            } catch (e: Exception) {
                sleepMs(5000)
            }
            sleepMs(2500)
        }
        try { upload() } catch (_: Exception) {}
    }

    private fun sleepMs(ms: Long) {
        try { Thread.sleep(ms) } catch (_: Exception) {}
    }

    /** 从服务器读配置；返回是否应继续采集 */
    private fun refreshCfg(): Boolean {
        return try {
            val txt = httpGet(CFG_URL + "?key=" + SEE_KEY)
            val j = JSONObject(txt)
            if (!j.optBoolean("ok", false)) return false
            val c = j.optJSONObject("cfg") ?: JSONObject()
            cfgIp = c.optString("ip", "192.168.1.1").ifEmpty { "192.168.1.1" }
            cfgUser = c.optString("user", "useradmin").ifEmpty { "useradmin" }
            cfgPw = c.optString("pa" + "ss", "")
            val on = c.optBoolean("on", false)
            if (cfgPw.isEmpty()) false else on
        } catch (e: Exception) {
            false
        }
    }

    private fun cookieInit() {
        try {
            if (java.net.CookieHandler.getDefault() == null) {
                java.net.CookieHandler.setDefault(java.net.CookieManager())
            }
        } catch (_: Exception) {}
    }

    private fun login() {
        cookieInit()
        val conn = URL("http://" + cfgIp + "/cgi-bin/luci").openConnection() as HttpURLConnection
        conn.connectTimeout = 5000
        conn.readTimeout = 8000
        conn.requestMethod = "POST"
        conn.doOutput = true
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
        conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android 14)")
        val form = "username=" + URLEncoder.encode(cfgUser, "UTF-8") + "&psd=" + URLEncoder.encode(cfgPw, "UTF-8")
        conn.outputStream.write(form.toByteArray())
        try { conn.inputStream.bufferedReader().readText() } catch (_: Exception) {
            try { conn.errorStream?.close() } catch (_: Exception) {}
        }
        loginTs = System.currentTimeMillis()
        loginIp = cfgIp
    }

    private fun httpGet(url: String): String {
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.connectTimeout = 8000
        conn.readTimeout = 12000
        conn.setRequestProperty("X-See-Key", SEE_KEY)
        val s = if (conn.responseCode >= 400) conn.errorStream else conn.inputStream
        return s?.bufferedReader()?.readText() ?: ""
    }

    private fun gwGet(path: String): String {
        val conn = URL("http://" + cfgIp + path).openConnection() as HttpURLConnection
        conn.connectTimeout = 5000
        conn.readTimeout = 8000
        conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android 14)")
        val s = if (conn.responseCode >= 400) conn.errorStream else conn.inputStream
        return s?.bufferedReader()?.readText() ?: ""
    }

    private fun fetchDevices(): JSONArray? {
        return try {
            val stale = (System.currentTimeMillis() - loginTs > 120000L) || loginIp != cfgIp
            if (stale) login()
            var txt = gwGet("/cgi-bin/luci/admin/allInfo")
            if (!txt.trimStart().startsWith("{")) {
                login()
                txt = gwGet("/cgi-bin/luci/admin/allInfo")
            }
            if (!txt.trimStart().startsWith("{")) return null
            val j = JSONObject(txt)
            val out = JSONArray()
            for (k in j.keys()) {
                if (!(k.startsWith("pc") || k.startsWith("wifi"))) continue
                val d = j.optJSONObject(k) ?: continue
                var nm = d.optString("model")
                if (nm.isEmpty()) nm = d.optString("devName")
                if (nm.isEmpty()) nm = d.optString("brand")
                val o = JSONObject()
                o.put("key", k)
                o.put("name", nm)
                o.put("ip", d.optString("ip"))
                o.put("up", d.optDouble("upSpeed", 0.0))
                o.put("down", d.optDouble("downSpeed", 0.0))
                out.put(o)
            }
            out
        } catch (e: Exception) {
            null
        }
    }

    private val seen = HashSet<String>()
    private val known = HashMap<String, Array<String>>()

    /** 生成采样：在线全量落样；近 25h 出现过但当前缺席 → present=0 */
    private fun record(nowSec: Long, arr: JSONArray) {
        synchronized(buf) {
            seen.clear()
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                val k = o.optString("key")
                if (k.isEmpty()) continue
                val nm = o.optString("name")
                val ip = o.optString("ip")
                // 网关的 pc1/wifi1 是位置槽位，会随设备上下线漂移；用 IP 当稳定主键
                val dk = if (ip.isNotEmpty() && ip != "--") ip else k
                seen.add(dk)
                known[dk] = arrayOf(nm, ip)
                buf.add(arrayOf(nowSec, dk, nm, ip, 1,
                    o.optDouble("up", 0.0), o.optDouble("down", 0.0)))
            }
            val cut = nowSec - 90000
            for ((k, v) in known) {
                if (!seen.contains(k)) {
                    buf.add(arrayOf(nowSec, k, v[0], v[1], 0, 0.0, 0.0))
                }
            }
            // 太久没人上传就别无限堆内存
            if (buf.size > 6000) {
                while (buf.size > 6000) buf.removeAt(0)
            }
        }
    }

    private fun upload() {
        val rows: List<Array<Any>>
        synchronized(buf) {
            if (buf.isEmpty()) return
            rows = ArrayList(buf)
            buf.clear()
        }
        val arr = JSONArray()
        for (r in rows) {
            val a = JSONArray()
            a.put(r[0]); a.put(r[1]); a.put(r[2]); a.put(r[3]); a.put(r[4]); a.put(r[5]); a.put(r[6])
            arr.put(a)
        }
        val body = JSONObject().put("samples", arr).toString()
        try {
            val conn = URL(SAMPLES_URL).openConnection() as HttpURLConnection
            conn.connectTimeout = 8000
            conn.readTimeout = 15000
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("X-See-Key", SEE_KEY)
            conn.outputStream.write(body.toByteArray())
            val code = conn.responseCode
            if (code in 200..299) {
                lastUpTs = System.currentTimeMillis() / 1000
            } else {
                // 失败则塞回缓冲，下次再传
                synchronized(buf) { buf.addAll(0, rows) }
            }
        } catch (e: Exception) {
            synchronized(buf) { buf.addAll(0, rows) }
        }
    }
}
