package com.mingkun.see

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

class Db(ctx: Context) : SQLiteOpenHelper(ctx, "see.db", null, 2) {
    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL("""CREATE TABLE devices(
            mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT DEFAULT '', vendor TEXT DEFAULT '',
            first_seen INTEGER DEFAULT 0, last_seen INTEGER DEFAULT 0)""")
        db.execSQL("""CREATE TABLE events(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, type TEXT,
            ip TEXT, mac TEXT, hostname TEXT DEFAULT '')""")
        createSamples(db)
    }

    override fun onUpgrade(db: SQLiteDatabase, o: Int, n: Int) {
        if (o < 2) createSamples(db)
    }

    private fun createSamples(db: SQLiteDatabase) {
        db.execSQL("""CREATE TABLE IF NOT EXISTS gw_samples(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, devkey TEXT,
            name TEXT DEFAULT '', ip TEXT DEFAULT '', present INTEGER DEFAULT 0,
            up REAL DEFAULT 0, down REAL DEFAULT 0)""")
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_gw_ts ON gw_samples(ts)")
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_gw_key ON gw_samples(devkey, ts)")
    }

    fun upsert(mac: String, ip: String, hostname: String, vendor: String, ts: Long) {
        val cv = ContentValues()
        cv.put("mac", mac); cv.put("ip", ip); cv.put("last_seen", ts)
        if (hostname.isNotEmpty()) cv.put("hostname", hostname)
        if (vendor.isNotEmpty()) cv.put("vendor", vendor)
        val cur = readableDatabase.query("devices", arrayOf("mac"), "mac=?", arrayOf(mac), null, null, null)
        val exists = cur.count > 0; cur.close()
        if (exists) {
            writableDatabase.update("devices", cv, "mac=?", arrayOf(mac))
        } else {
            cv.put("first_seen", ts)
            writableDatabase.insertWithOnConflict("devices", null, cv, SQLiteDatabase.CONFLICT_REPLACE)
        }
    }

    fun devices(): List<Array<String>> {
        val out = mutableListOf<Array<String>>()
        val c = readableDatabase.query("devices", arrayOf("mac", "ip", "hostname", "vendor"), null, null, null, null, "last_seen DESC")
        while (c.moveToNext()) out.add(arrayOf(c.getString(0), c.getString(1), c.getString(2), c.getString(3)))
        c.close(); return out
    }

    fun addEvent(ts: Long, type: String, ip: String, mac: String, hostname: String) {
        val cv = ContentValues()
        cv.put("ts", ts); cv.put("type", type); cv.put("ip", ip); cv.put("mac", mac); cv.put("hostname", hostname)
        writableDatabase.insert("events", null, cv)
    }

    /** 清空观察页历史：动态事件记录 + 已发现设备（避免下次启动把旧设备回填进列表）。 */
    fun clearHistory() {
        writableDatabase.delete("events", null, null)
        writableDatabase.delete("devices", null, null)
    }

    /** 删除单台设备（用于清掉混进来的外网段设备）。 */
    fun deleteDevice(mac: String) {
        writableDatabase.delete("devices", "mac=?", arrayOf(mac))
    }

    // ---- 网关流量采样 ----

    fun addSample(ts: Long, devkey: String, name: String, ip: String, present: Int, up: Double, down: Double) {
        val cv = ContentValues()
        cv.put("ts", ts); cv.put("devkey", devkey); cv.put("name", name); cv.put("ip", ip)
        cv.put("present", present); cv.put("up", up); cv.put("down", down)
        writableDatabase.insert("gw_samples", null, cv)
    }

    /** 近 since 秒内出现过的设备（key/name/ip），用于补记「缺席」样本 */
    fun gwKeys(since: Long): List<Array<String>> {
        val out = mutableListOf<Array<String>>()
        val c = readableDatabase.rawQuery(
            "SELECT devkey, MAX(name), MAX(ip) FROM gw_samples WHERE ts >= ? GROUP BY devkey",
            arrayOf(since.toString()))
        while (c.moveToNext()) out.add(arrayOf(c.getString(0), c.getString(1) ?: "", c.getString(2) ?: ""))
        c.close(); return out
    }

    /** 返回 [ts(秒), present, up, down] */
    fun gwSeries(devkey: String, from: Long, to: Long): List<DoubleArray> {
        val out = mutableListOf<DoubleArray>()
        val c = readableDatabase.rawQuery(
            "SELECT ts, present, up, down FROM gw_samples WHERE devkey=? AND ts>=? AND ts<? ORDER BY ts",
            arrayOf(devkey, from.toString(), to.toString()))
        while (c.moveToNext()) {
            out.add(doubleArrayOf(c.getLong(0).toDouble(), c.getInt(1).toDouble(), c.getDouble(2), c.getDouble(3)))
        }
        c.close(); return out
    }

    fun pruneSamples(before: Long) {
        writableDatabase.delete("gw_samples", "ts < ?", arrayOf(before.toString()))
    }
}
