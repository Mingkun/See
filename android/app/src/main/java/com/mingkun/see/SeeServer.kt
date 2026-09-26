package com.mingkun.see

import android.content.Context
import fi.iki.elonen.NanoHTTPD
import fi.iki.elonen.NanoHTTPD.Response.Status
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.net.HttpURLConnection

class SeeServer(private val ctx: Context, private val scanner: Scanner, private val phoneIp: String, private val db: Db) : NanoHTTPD(5050) {

    override fun serve(session: IHTTPSession): Response {
        return try {
            when (session.uri ?: "/") {
                "/" -> html()
                "/api/status" -> status()
                "/api/devices" -> devices()
                "/api/events" -> events(session)
                "/api/device" -> device(session)
                "/api/scan" -> scanNow()
                "/api/gw/probe" -> gwProbe(session)
                "/api/gw/devices" -> gwDevices(session)
                "/api/gw/analysis" -> gwAnalysis(session)
                "/api/gw/keys" -> gwKeys()
                else -> newFixedLengthResponse(Status.NOT_FOUND, "text/plain", "404")
            }
        } catch (e: Exception) {
            newFixedLengthResponse(Status.INTERNAL_ERROR, "application/json",
                JSONObject().put("ok", false).put("error", "${e.message}").toString())
        }
    }

    private fun gwProbe(session: IHTTPSession): Response {
        val map = HashMap<String, String>()
        session.parseBody(map)
        val body = map["postData"] ?: ""
        val ip: String
        var ml = 3000
        val paths = ArrayList<Any>()
        try {
            val req = JSONObject(body)
            ip = req.optString("ip", "192.168.1.1")
            ml = Math.max(200, Math.min(req.optInt("maxlen", 3000), 30000))
            val arr = req.optJSONArray("paths") ?: JSONArray()
            for (i in 0 until arr.length()) paths.add(arr.get(i))
        } catch (e: Exception) {
            return newFixedLengthResponse(Status.BAD_REQUEST, "application/json",
                JSONObject().put("ok", false).put("error", "bad json").toString())
        }
        try {
            if (java.net.CookieHandler.getDefault() == null) {
                java.net.CookieHandler.setDefault(java.net.CookieManager())
            }
        } catch (e: Exception) {}
        val results = JSONArray()
        for (item in paths) {
            val r = JSONObject()
            var path = ""
            var method = "GET"
            var bodyStr: String? = null
            var ctype = "application/json"
            try {
                if (item is org.json.JSONArray) {
                    // ["路径","方法","body","content-type"]
                    path = (item as org.json.JSONArray).optString(0, "")
                    method = (item as org.json.JSONArray).optString(1, "GET")
                    bodyStr = (item as org.json.JSONArray).optString(2, "")
                    ctype = (item as org.json.JSONArray).optString(3, "application/json")
                } else {
                    path = item.toString()
                }
            } catch (e: Exception) { path = item.toString() }
            r.put("path", method + " " + path)
            try {
                val url = java.net.URL("http://" + ip + path)
                val conn = url.openConnection() as HttpURLConnection
                conn.connectTimeout = 4000
                conn.readTimeout = 4000
                conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36")
                conn.requestMethod = method
                if (bodyStr != null && bodyStr.isNotEmpty()) {
                    conn.doOutput = true
                    conn.setRequestProperty("Content-Type", ctype)
                    conn.outputStream.write(bodyStr.toByteArray())
                }
                r.put("status", conn.responseCode)
                val stream = if (conn.responseCode >= 400) conn.errorStream else conn.inputStream
                val text = stream?.bufferedReader()?.readText() ?: ""
                r.put("len", text.length)
                r.put("snippet", text.take(ml))
            } catch (e: Exception) {
                r.put("status", -1)
                r.put("err", (e.message ?: "err").take(80))
            }
            results.put(r)
        }
        return json(JSONObject().put("ok", true).put("results", results))
    }

    @Volatile private var gwLoginTs = 0L
    @Volatile private var gwLoginIp = ""
    @Volatile private var lastRecTs = 0L
    @Volatile private var lastPruneTs = 0L

    private fun gwDevices(session: IHTTPSession): Response {
        val map = HashMap<String, String>()
        session.parseBody(map)
        val raw = map["postData"] ?: ""
        val ip: String
        val user: String
        val pw: String
        try {
            val req = JSONObject(raw)
            ip = req.optString("ip", "192.168.1.1").trim().ifEmpty { "192.168.1.1" }
            user = req.optString("user", "useradmin").trim().ifEmpty { "useradmin" }
            pw = req.optString("pa" + "ss", "")
        } catch (e: Exception) {
            return newFixedLengthResponse(Status.BAD_REQUEST, "application/json",
                JSONObject().put("ok", false).put("error", "bad json").toString())
        }
        try {
            if (java.net.CookieHandler.getDefault() == null) {
                java.net.CookieHandler.setDefault(java.net.CookieManager())
            }
        } catch (e: Exception) {}
        return try {
            val stale = (System.currentTimeMillis() - gwLoginTs > 120000L) || gwLoginIp != ip
            if (stale) gwLogin(ip, user, pw)
            var txt = gwGet(ip, "/cgi-bin/luci/admin/allInfo")
            if (!txt.trimStart().startsWith("{")) {
                gwLogin(ip, user, pw)
                txt = gwGet(ip, "/cgi-bin/luci/admin/allInfo")
            }
            if (!txt.trimStart().startsWith("{")) {
                newFixedLengthResponse(Status.OK, "application/json",
                    JSONObject().put("ok", false).put("error", "登录未成功，请检查账号与密码").toString())
            } else {
                val j = JSONObject(txt)
                val arr = JSONArray()
                for (k in j.keys()) {
                    if (!(k.startsWith("pc") || k.startsWith("wifi"))) continue
                    val d = j.optJSONObject(k) ?: continue
                    val o = JSONObject()
                    o.put("key", k)
                    o.put("link", if (k.startsWith("wifi")) "wifi" else "wired")
                    var nm = d.optString("model")
                    if (nm.isEmpty()) nm = d.optString("devName")
                    if (nm.isEmpty()) nm = d.optString("brand")
                    o.put("name", nm)
                    o.put("brand", d.optString("brand"))
                    o.put("ip", d.optString("ip"))
                    o.put("type", d.optString("type"))
                    o.put("online_time", d.optInt("onlineTime", 0))
                    o.put("up", d.optDouble("upSpeed", 0.0))
                    o.put("down", d.optDouble("downSpeed", 0.0))
                    arr.put(o)
                }
                val t = JSONObject()
                t.put("wdown", j.optDouble("tWDown", 0.0)); t.put("wup", j.optDouble("tWUp", 0.0))
                t.put("wldown", j.optDouble("tWlDown", 0.0)); t.put("wlup", j.optDouble("tWlUp", 0.0))
                t.put("wired", j.optInt("wcount", 0)); t.put("wireless", j.optInt("wlcount", 0))
                t.put("wan_connected", j.optString("wanConnect", ""))
                t.put("wan_uptime", j.optInt("wanUpTime", 0))
                val nowSec = System.currentTimeMillis() / 1000
                recSamples(nowSec, arr)
                json(JSONObject().put("ok", true).put("devices", arr).put("totals", t)
                    .put("ts", nowSec))
            }
        } catch (e: Exception) {
            newFixedLengthResponse(Status.OK, "application/json",
                JSONObject().put("ok", false).put("error", (e.message ?: "err").take(120)).toString())
        }
    }

    private fun gwLogin(ip: String, user: String, pw: String) {
        val conn = (java.net.URL("http://" + ip + "/cgi-bin/luci")).openConnection() as HttpURLConnection
        conn.connectTimeout = 4000
        conn.readTimeout = 6000
        conn.requestMethod = "POST"
        conn.doOutput = true
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
        conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android 14)")
        val form = "username=" + java.net.URLEncoder.encode(user, "UTF-8") + "&psd=" +
            java.net.URLEncoder.encode(pw, "UTF-8")
        conn.outputStream.write(form.toByteArray())
        try {
            conn.inputStream.bufferedReader().readText()
        } catch (e: Exception) {
            try { conn.errorStream?.close() } catch (e2: Exception) {}
        }
        gwLoginTs = System.currentTimeMillis()
        gwLoginIp = ip
    }

    private fun gwGet(ip: String, path: String): String {
        val conn = (java.net.URL("http://" + ip + path)).openConnection() as HttpURLConnection
        conn.connectTimeout = 4000
        conn.readTimeout = 6000
        conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android 14)")
        val s = if (conn.responseCode >= 400) conn.errorStream else conn.inputStream
        return s?.bufferedReader()?.readText() ?: ""
    }

    /** 每次拉取网关后落采样：在场记实时速率，不在场记 present=0（休眠/离线） */
    private fun recSamples(nowSec: Long, arr: JSONArray) {
        if (nowSec - lastRecTs < 10) return
        lastRecTs = nowSec
        try {
            val present = HashMap<String, JSONObject>()
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                present[o.optString("key")] = o
            }
            for (k in db.gwKeys(nowSec - 90000)) {
                val d = present[k[0]]
                if (d != null) {
                    db.addSample(nowSec, k[0], d.optString("name"), d.optString("ip"), 1,
                        d.optDouble("up", 0.0), d.optDouble("down", 0.0))
                } else {
                    db.addSample(nowSec, k[0], k[1], k[2], 0, 0.0, 0.0)
                }
            }
            if (nowSec - lastPruneTs > 3600) {
                lastPruneTs = nowSec
                db.pruneSamples(nowSec - 7 * 86400L)
            }
        } catch (e: Exception) {}
    }

    private fun gwKeys(): Response {
        val now = System.currentTimeMillis() / 1000
        val arr = JSONArray()
        try {
            for (k in db.gwKeys(now - 7 * 86400L)) {
                arr.put(JSONObject().put("key", k[0]).put("name", k[1]).put("ip", k[2]))
            }
        } catch (e: Exception) {}
        return json(JSONObject().put("ok", true).put("keys", arr).put("now", now))
    }

    /** 返回最近 hours 小时的分钟级负载曲线（速率取均值），含在场标记 */
    private fun gwAnalysis(session: IHTTPSession): Response {
        val map = HashMap<String, String>()
        session.parseBody(map)
        val raw = map["postData"] ?: ""
        val key: String
        val hours: Int
        try {
            val req = JSONObject(raw)
            key = req.optString("key", "")
            hours = Math.max(1, Math.min(req.optInt("hours", 24), 48))
        } catch (e: Exception) {
            return newFixedLengthResponse(Status.BAD_REQUEST, "application/json",
                JSONObject().put("ok", false).put("error", "bad json").toString())
        }
        if (key.isEmpty()) {
            return newFixedLengthResponse(Status.OK, "application/json",
                JSONObject().put("ok", false).put("error", "未指定设备").toString())
        }
        return try {
            val now = System.currentTimeMillis() / 1000
            val from = now - hours * 3600L
            val n = hours * 60
            val speed = DoubleArray(n); val cnt = IntArray(n)
            val pres = IntArray(n); val has = IntArray(n)
            for (r in db.gwSeries(key, from, now + 1)) {
                val m = ((r[0].toLong() - from) / 60).toInt()
                if (m < 0 || m >= n) continue
                has[m] = 1
                if (r[1] > 0.5) { pres[m] = 1; speed[m] += (r[2] + r[3]); cnt[m] += 1 }
            }
            var name = ""; var ip = ""
            for (k in db.gwKeys(from)) if (k[0] == key) { name = k[1]; ip = k[2] }
            val sp = JSONArray(); val pr = JSONArray(); val hs = JSONArray()
            for (i in 0 until n) {
                sp.put(if (cnt[i] > 0) speed[i] / cnt[i] else 0.0)
                pr.put(pres[i]); hs.put(has[i])
            }
            json(JSONObject().put("ok", true).put("key", key).put("name", name).put("ip", ip)
                .put("from", from).put("now", now).put("minutes", n)
                .put("speed", sp).put("present", pr).put("has", hs))
        } catch (e: Exception) {
            newFixedLengthResponse(Status.OK, "application/json",
                JSONObject().put("ok", false).put("error", (e.message ?: "err").take(120)).toString())
        }
    }

    private fun scanNow(): Response {
        scanner.scanNow()
        return json(JSONObject().put("ok", true))
    }

    private fun json(o: JSONObject): Response =
        newFixedLengthResponse(Status.OK, "application/json", o.toString())

    private fun html(): Response {
        val bytes = ctx.assets.open("index.html").readBytes()
        return newFixedLengthResponse(Status.OK, "text/html", ByteArrayInputStream(bytes), bytes.size.toLong())
    }

    private fun status(): Response {
        var online = 0
        var total = 0
        synchronized(scanner.lock) {
            total = scanner.devices.size
            online = scanner.devices.values.count { it.online }
        }
        val o = JSONObject()
        o.put("ok", true); o.put("mode", "observer"); o.put("iface", "wifi"); o.put("ver", "2.18"); o.put("vercode", 29)
        o.put("subnet", scanner.subnet); o.put("ip", phoneIp)
        o.put("uptime", System.currentTimeMillis() / 1000 - scanner.startTs)
        o.put("online", online); o.put("devices", total)
        val sp = JSONObject(); sp.put("up", 0); sp.put("down", 0)
        o.put("total_speed", sp); o.put("pkt_count", 0)
        o.put("scan_error", scanner.lastError); o.put("last_sweep", scanner.lastSweep)
        return json(o)
    }

    private fun devices(): Response {
        val arr = JSONArray()
        synchronized(scanner.lock) {
            for ((mac, d) in scanner.devices) {
                val v = JSONObject()
                v.put("mac", if (mac.startsWith("ip:")) "" else mac); v.put("ip", d.ip); v.put("hostname", d.hostname)
                v.put("vendor", d.vendor); v.put("type", d.type); v.put("online", d.online); v.put("last_seen", d.lastSeen)
                v.put("speed", zeros()); v.put("session", zeros()); v.put("today", zeros())
                arr.put(v)
            }
        }
        return json(JSONObject().put("ok", true).put("devices", arr))
    }

    private fun zeros(): JSONObject {
        val z = JSONObject(); z.put("up", 0); z.put("down", 0); return z
    }

    private fun events(session: IHTTPSession): Response {
        val limit = (session.parameters["limit"]?.firstOrNull() ?: "60").toIntOrNull() ?: 60
        val arr = JSONArray()
        synchronized(scanner.lock) {
            for (e in scanner.events.take(limit.coerceAtMost(300))) {
                arr.put(JSONObject().put("ts", e.ts).put("type", e.type).put("ip", e.ip)
                    .put("mac", e.mac).put("hostname", e.hostname))
            }
        }
        return json(JSONObject().put("ok", true).put("events", arr))
    }

    private fun device(session: IHTTPSession): Response {
        val ip = session.parameters["ip"]?.firstOrNull() ?: ""
        if (ip.isEmpty()) return newFixedLengthResponse(Status.BAD_REQUEST, "application/json",
            JSONObject().put("ok", false).put("error", "missing ip").toString())
        var dev: Scanner.Dev? = null
        var mac = ""
        synchronized(scanner.lock) {
            for ((m, d) in scanner.devices) if (d.ip == ip) { dev = d; mac = m; break }
        }
        val v = JSONObject()
        if (dev != null) {
            v.put("mac", if (mac.startsWith("ip:")) "" else mac); v.put("ip", ip); v.put("hostname", dev!!.hostname)
            v.put("vendor", dev!!.vendor); v.put("type", dev!!.type); v.put("online", dev!!.online); v.put("last_seen", dev!!.lastSeen)
        } else {
            v.put("mac", ""); v.put("ip", ip); v.put("hostname", ""); v.put("vendor", ""); v.put("type", "")
            v.put("online", false); v.put("last_seen", 0)
        }
        return json(JSONObject().put("ok", true).put("device", v)
            .put("series", JSONArray()).put("apps", JSONArray())
            .put("today", zeros()).put("session", zeros()))
    }
}
