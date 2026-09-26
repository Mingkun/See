package com.mingkun.see

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkRequest
import android.os.Bundle
import android.webkit.WebView
import java.net.Inet4Address

class MainActivity : Activity() {
    private lateinit var web: WebView
    private lateinit var server: SeeServer
    private lateinit var scanner: Scanner
    private lateinit var db: Db

    private val netCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = refreshNet()
        override fun onLost(network: Network) = refreshNet()
    }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        db = Db(this)
        scanner = Scanner(db)
        scanner.subnet = detectSubnet()
        server = SeeServer(this, scanner, localIp())
        server.start()
        scanner.start()
        try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            cm.registerNetworkCallback(NetworkRequest.Builder().build(), netCallback)
        } catch (_: Exception) {
        }
        web = WebView(this)
        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        setContentView(web)
        if (savedInstanceState != null) web.restoreState(savedInstanceState)
        else web.loadUrl("http://127.0.0.1:5050/")
    }

    private fun refreshNet() {
        val s = detectSubnet()
        if (s.isNotBlank()) scanner.subnet = s
    }

    private fun ipInfo(): Pair<String, Int>? {
        return try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val lp = cm.getLinkProperties(cm.activeNetwork) ?: return null
            for (la in lp.linkAddresses) {
                val a = la.address
                if (a is Inet4Address && !a.isLoopbackAddress) return Pair(a.hostAddress ?: continue, la.prefixLength)
            }
            null
        } catch (_: Exception) {
            null
        }
    }

    private fun localIp(): String = ipInfo()?.first ?: "0.0.0.0"

    private fun detectSubnet(): String {
        val (ip, prefix) = ipInfo() ?: return ""
        val p = ip.split('.').map { it.toIntOrNull() ?: 0 }
        val v = ((p[0] shl 24) or (p[1] shl 16) or (p[2] shl 8) or p[3]).toLong() and 0xFFFFFFFFL
        val mask = (-1L shl (32 - prefix)) and 0xFFFFFFFFL
        val base = v and mask
        val net = "${(base shr 24) and 255}.${(base shr 16) and 255}.${(base shr 8) and 255}.${base and 255}"
        return "$net/$prefix"
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        web.saveState(outState)
    }

    override fun onDestroy() {
        try { server.stop() } catch (_: Exception) {}
        scanner.interrupt()
        super.onDestroy()
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        if (web.canGoBack()) web.goBack() else super.onBackPressed()
    }
}
