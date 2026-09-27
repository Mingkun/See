package com.mingkun.see

import java.util.concurrent.ConcurrentHashMap

/**
 * 网关侧「在网设备」快照。
 *
 * GwService 每轮从网关 allInfo 拉到设备表后写入这里；Scanner 每轮扫描时合并。
 *
 * 为什么需要：手机侧的发现手段只有 ICMP ping + /proc/net/arp，实测两个都会漏：
 *  - 新安卓（10+）应用读不到 /proc/net/arp，只能靠 ping 回包；
 *  - WiFi 低功耗模块（IoT）在 DTIM 休眠里常常不回 ping；
 *  - 路由器若开了 AP / 二层隔离，手机根本到不了对方。
 * 但网关自己是 AP，设备连着它它就知道（监控页数据就来自这里），所以用网关数据兜底，
 * 避免出现「监控页有数据、观察页却显示离线」。
 */
object GwFeed {
    /** ip -> [名称, 写入时刻秒] */
    private val map = ConcurrentHashMap<String, Array<String>>()

    fun put(ip: String, name: String, ts: Long) {
        if (ip.isEmpty() || ip == "--") return
        map[ip] = arrayOf(name, ts.toString())
    }

    /** 只保留本轮网关仍报在线的 ip，其余删掉，避免设备真下线后这边永远显示在线 */
    fun retain(seenIps: Set<String>) {
        val it = map.keys.iterator()
        while (it.hasNext()) if (!seenIps.contains(it.next())) it.remove()
    }

    /** 近 freshSec 秒内被网关确认在线的设备：ip -> 名称 */
    fun fresh(nowSec: Long, freshSec: Long): Map<String, String> {
        val out = HashMap<String, String>()
        for ((ip, v) in map) {
            val ts = v[1].toLongOrNull() ?: 0L
            if (nowSec - ts <= freshSec) out[ip] = v[0]
        }
        return out
    }
}
