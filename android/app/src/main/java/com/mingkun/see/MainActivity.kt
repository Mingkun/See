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
    private var filePathCallback: android.webkit.ValueCallback<Array<android.net.Uri>>? = null
    private var updateDownloadId = -1L

    inner class Bridge {
        @android.webkit.JavascriptInterface
        fun confirmUpdate(ver: String, url: String) {
            runOnUiThread {
                android.app.AlertDialog.Builder(this@MainActivity)
                    .setTitle("发现新版本")
                    .setMessage("see v" + ver + " 可用，下载并安装？")
                    .setPositiveButton("下载") { _, _ -> downloadAndInstall(url) }
                    .setNegativeButton("取消", null)
                    .show()
            }
        }
    }

    private fun downloadAndInstall(url: String) {
        try {
            val request = android.app.DownloadManager.Request(android.net.Uri.parse(url))
            request.setTitle("see 更新")
            request.setMimeType("application/vnd.android.package-archive")
            request.addRequestHeader("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
            request.setNotificationVisibility(android.app.DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
            request.setDestinationInExternalFilesDir(this, null, "see-update.apk")
            val dm = getSystemService(DOWNLOAD_SERVICE) as android.app.DownloadManager
            updateDownloadId = dm.enqueue(request)
        } catch (e: Exception) {
            try { startActivity(android.content.Intent(android.content.Intent.ACTION_VIEW, android.net.Uri.parse(url))) } catch (_: Exception) {}
        }
    }

    private fun openDownloadedApk() {
        try {
            val dir = getExternalFilesDir(null) ?: return
            val file = java.io.File(dir, "see-update.apk")
            if (!file.exists()) return
            val uri = androidx.core.content.FileProvider.getUriForFile(this, "$packageName.fileprovider", file)
            val install = android.content.Intent(android.content.Intent.ACTION_VIEW)
            install.setDataAndType(uri, "application/vnd.android.package-archive")
            install.addFlags(android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION)
            install.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
            startActivity(install)
        } catch (e: Exception) { e.printStackTrace() }
    }

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
        scanner.selfIp = localIp()
        scanner.gateway = gwIp()
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
        web.addJavascriptInterface(Bridge(), "SeeBridge")
        web.webChromeClient = object : android.webkit.WebChromeClient() {
            override fun onShowFileChooser(wv: WebView?, cb: android.webkit.ValueCallback<Array<android.net.Uri>>, params: android.webkit.WebChromeClient.FileChooserParams?): Boolean {
                filePathCallback?.onReceiveValue(null)
                filePathCallback = cb
                val pick = android.content.Intent(android.content.Intent.ACTION_GET_CONTENT)
                pick.addCategory(android.content.Intent.CATEGORY_OPENABLE)
                pick.type = "image/*"
                pick.putExtra(android.content.Intent.EXTRA_ALLOW_MULTIPLE, true)
                return try {
                    startActivityForResult(android.content.Intent.createChooser(pick, "选择截图"), 1001)
                    true
                } catch (e: Exception) {
                    filePathCallback = null
                    false
                }
            }
        }
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
                                "<h2>see v2.4</h2><p>本机服务连接失败</p>" +
                                "<p style='color:#b02a37;font-size:13px'>" + msg + "</p>" +
                                "<p style='font-size:12px;color:#666'>点返回键或重新打开应用重试</p></body></html>",
                                "text/html", "utf-8", null)
                        }, 600)
                    }
                }
            }
        }
        setContentView(web)
        registerReceiver(object : android.content.BroadcastReceiver() {
            override fun onReceive(context: android.content.Context?, intent: android.content.Intent?) {
                val id = intent?.getLongExtra(android.app.DownloadManager.EXTRA_DOWNLOAD_ID, -1L) ?: -1L
                if (id > 0 && id == updateDownloadId) openDownloadedApk()
            }
        }, android.content.IntentFilter(android.app.DownloadManager.ACTION_DOWNLOAD_COMPLETE))
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
        val g = gwIp()
        if (g.isNotBlank()) scanner.gateway = g
    }

    private fun gwIp(): String {
        return try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val lp = cm.getLinkProperties(cm.activeNetwork) ?: return ""
            for (r in lp.routes) {
                val g = r.gateway?.hostAddress
                if (!g.isNullOrEmpty()) return g
            }
            ""
        } catch (_: Exception) { "" }
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

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: android.content.Intent?) {
        if (requestCode == 1001) {
            val cb = filePathCallback ?: return
            filePathCallback = null
            val uris = ArrayList<android.net.Uri>()
            if (resultCode == RESULT_OK && data != null) {
                val clip = data.clipData
                if (clip != null) for (i in 0 until clip.itemCount) clip.getItemAt(i).uri?.let { u -> uris.add(u) }
                if (uris.isEmpty()) data.data?.let { u -> uris.add(u) }
            }
            cb.onReceiveValue(uris.toTypedArray())
            return
        }
        super.onActivityResult(requestCode, resultCode, data)
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
