package com.mingkun.see

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

class Db(ctx: Context) : SQLiteOpenHelper(ctx, "see.db", null, 1) {
    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL("""CREATE TABLE devices(
            mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT DEFAULT '', vendor TEXT DEFAULT '',
            first_seen INTEGER DEFAULT 0, last_seen INTEGER DEFAULT 0)""")
        db.execSQL("""CREATE TABLE events(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, type TEXT,
            ip TEXT, mac TEXT, hostname TEXT DEFAULT '')""")
    }

    override fun onUpgrade(db: SQLiteDatabase, o: Int, n: Int) {}

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
}
