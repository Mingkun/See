package com.mingkun.see

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.PowerManager

/**
 * 防 Doze 冻结：前台服务在省电休眠（Doze）下会被系统挂起，导致采样出现数小时空洞。
 * 这里用 AlarmManager 的「空闲也允许」闹钟每 15 分钟把服务拉起来一次，采一轮再睡。
 */
object GwAlarm {
    private const val REQ = 4201
    const val ACTION = "com.mingkun.see.KICK"
    private const val EVERY_MS = 15L * 60L * 1000L

    private fun pi(ctx: Context): PendingIntent {
        val i = Intent(ctx, GwAlarmReceiver::class.java).setAction(ACTION)
        var f = PendingIntent.FLAG_UPDATE_CURRENT
        if (Build.VERSION.SDK_INT >= 23) f = f or PendingIntent.FLAG_IMMUTABLE
        return PendingIntent.getBroadcast(ctx, REQ, i, f)
    }

    fun schedule(ctx: Context) {
        try {
            val am = ctx.getSystemService(Context.ALARM_SERVICE) as AlarmManager
            val at = System.currentTimeMillis() + EVERY_MS
            if (Build.VERSION.SDK_INT >= 23) {
                am.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, at, pi(ctx))
            } else {
                am.set(AlarmManager.RTC_WAKEUP, at, pi(ctx))
            }
        } catch (_: Exception) {
        }
    }

    fun cancel(ctx: Context) {
        try {
            val am = ctx.getSystemService(Context.ALARM_SERVICE) as AlarmManager
            am.cancel(pi(ctx))
        } catch (_: Exception) {
        }
    }
}

class GwAlarmReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context?, intent: Intent?) {
        if (ctx == null) return
        try {
            GwService.start(ctx.applicationContext)
        } catch (_: Exception) {
        }
        GwAlarm.schedule(ctx.applicationContext)
    }
}

/** 采集期间持有 CPU 唤醒锁 + WiFi 锁，避免息屏后线程被彻底冻结。 */
class GwLocks(private val ctx: Context) {
    private var wake: PowerManager.WakeLock? = null
    private var wifi: android.net.wifi.WifiManager.WifiLock? = null

    fun acquire() {
        try {
            val pm = ctx.getSystemService(Context.POWER_SERVICE) as PowerManager
            wake = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "see:gw").apply {
                setReferenceCounted(false)
                acquire()
            }
        } catch (_: Exception) {
        }
        try {
            val wm = ctx.applicationContext.getSystemService(Context.WIFI_SERVICE) as android.net.wifi.WifiManager
            wifi = wm.createWifiLock(android.net.wifi.WifiManager.WIFI_MODE_FULL_HIGH_PERF, "see:wifi").apply {
                setReferenceCounted(false)
                acquire()
            }
        } catch (_: Exception) {
        }
    }

    fun release() {
        try { wake?.takeIf { it.isHeld }?.release() } catch (_: Exception) {}
        try { wifi?.takeIf { it.isHeld }?.release() } catch (_: Exception) {}
        wake = null
        wifi = null
    }
}
