package com.mingkun.see

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * 开机 / 应用更新后自启后台采集服务。
 * 服务启动后会自己从服务器读配置；若用户没开启实时设备，它会自行退出。
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context?, intent: Intent?) {
        if (ctx == null) return
        val a = intent?.action ?: return
        if (a == Intent.ACTION_BOOT_COMPLETED ||
            a == "android.intent.action.QUICKBOOT_POWERON" ||
            a == Intent.ACTION_MY_PACKAGE_REPLACED
        ) {
            try {
                GwService.start(ctx.applicationContext)
            } catch (_: Exception) {
            }
        }
    }
}
