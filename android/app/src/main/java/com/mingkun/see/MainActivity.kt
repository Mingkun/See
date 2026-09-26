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
    private var retries: Int? = 0

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
        web.webViewClient = object : android.webkit.WebViewClient() {
            override fun onReceivedError(view: WebView?, req: android.webkit.WebResourceRequest?, err: android.webkit.WebResourceError?) {
                if (req?.url?.toString()?.startsWith("http://127.0.0.1:5050") == true) {
                    retries = (retries ?: 0) + 1
                    if (retries!! < 5) web.postDelayed({ web.loadUrl("http://127.0.0.1:5050/") }, 800)
                    else {
                        val msg = (err?.description ?: "").toString()
                        web.postDelayed({
                            web.loadDataWithBaseURL(null,
                                "<html><body style='font-family:sans-serif;padding:24px;line-height:1.6'>" +
                                "<h2>see v1.7</h2><p>本机服务连接失败</p>" +
                                "<p style='color:#b02a37;font-size:13px'>" + msg + "</p>" +
                                "<p style='font-size:12px;color:#666'>点返回键或重新打开应用重试</p></body></html>",
                                "text/html", "utf-8", null)
                        }, 600)
                    }
                }
            }
        }
        setContentView(web)
        if (savedInstanceState != null) web.restoreState(savedInstanceState)
        else {
            Thread {
                var waited = 0
                while (!server.wasStarted() && waited < 3000) { Thread.sleep(100); waited += 100 }
                runOnUiThread { web.loadUrl("http://127.0.0.1:5050/") }
            }.start()
        }
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
