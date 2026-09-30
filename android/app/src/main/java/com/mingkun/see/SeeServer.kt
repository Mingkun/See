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

    private fun scanNow(): Response {
        // 用户要求：点「立即扫描」时先清空历史记录（设备表 + 动态），再重新扫描
        scanner.resetHistory()
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
        o.put("ok", true); o.put("mode", "observer"); o.put("iface", "wifi"); o.put("ver", "3.25"); o.put("vercode", 136)
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
