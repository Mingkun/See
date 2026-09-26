package com.mingkun.see

import android.content.Context
import fi.iki.elonen.NanoHTTPD
import fi.iki.elonen.NanoHTTPD.Response.Status
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream

class SeeServer(private val ctx: Context, private val scanner: Scanner, private val phoneIp: String) : NanoHTTPD(5050) {

    override fun serve(session: IHTTPSession): Response {
        return try {
            when (session.uri ?: "/") {
                "/" -> html()
                "/api/status" -> status()
                "/api/devices" -> devices()
                "/api/events" -> events(session)
                "/api/device" -> device(session)
                else -> newFixedLengthResponse(Status.NOT_FOUND, "text/plain", "404")
            }
        } catch (e: Exception) {
            newFixedLengthResponse(Status.INTERNAL_ERROR, "application/json",
                JSONObject().put("ok", false).put("error", "${e.message}").toString())
        }
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
        o.put("ok", true); o.put("mode", "observer"); o.put("iface", "wifi")
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
                v.put("mac", mac); v.put("ip", d.ip); v.put("hostname", d.hostname)
                v.put("vendor", d.vendor); v.put("online", d.online); v.put("last_seen", d.lastSeen)
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
            v.put("mac", mac); v.put("ip", ip); v.put("hostname", dev!!.hostname)
            v.put("vendor", dev!!.vendor); v.put("online", dev!!.online); v.put("last_seen", dev!!.lastSeen)
        } else {
            v.put("mac", ""); v.put("ip", ip); v.put("hostname", ""); v.put("vendor", "")
            v.put("online", false); v.put("last_seen", 0)
        }
        return json(JSONObject().put("ok", true).put("device", v)
            .put("series", JSONArray()).put("apps", JSONArray())
            .put("today", zeros()).put("session", zeros()))
    }
}
