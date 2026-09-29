package com.mingkun.see

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
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
    private var pendingApkName: String? = null
    private var pendingApkSize = 0L
    private var pendingApkMd5 = ""
    private var chartFs = false
    private var prevOrientation = android.content.pm.ActivityInfo.SCREEN_ORIENTATION_UNSPECIFIED

    private fun toast(msg: String) {
        try { android.widget.Toast.makeText(this, msg, android.widget.Toast.LENGTH_LONG).show() } catch (_: Exception) {}
    }

    private fun md5Of(f: java.io.File): String {
        return try {
            val md = java.security.MessageDigest.getInstance("MD5")
            f.inputStream().use { ins ->
                val buf = ByteArray(1 shl 16)
                while (true) {
                    val n = ins.read(buf)
                    if (n <= 0) break
                    md.update(buf, 0, n)
                }
            }
            md.digest().joinToString("") { "%02x".format(it) }
        } catch (_: Exception) { "" }
    }

    /**
     * 柱状图全屏：网页双击图表时调用。进全屏锁横屏、退出恢复原来的方向设置。
     * （网页侧只管样式与重绘，方向由这里控制，WebView 里不必依赖 Fullscreen API。）
     */
    inner class Bridge {
        @android.webkit.JavascriptInterface
        fun setChartFs(on: Boolean) {
            runOnUiThread {
                if (on) {
                    if (!chartFs) {
                        prevOrientation = requestedOrientation
                        chartFs = true
                    }
                    requestedOrientation = android.content.pm.ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE
                } else {
                    chartFs = false
                    requestedOrientation = prevOrientation
                }
            }
        }

        @android.webkit.JavascriptInterface
        fun confirmUpdate(ver: String, url: String, size: Double, md5: String) {
            runOnUiThread {
                android.app.AlertDialog.Builder(this@MainActivity)
                    .setTitle("发现新版本")
                    .setMessage("see v" + ver + " 可用，下载并安装？")
                    .setPositiveButton("下载") { _, _ -> downloadAndInstall(ver, url, size.toLong(), md5 ?: "") }
                    .setNegativeButton("取消", null)
                    .show()
            }
        }
    }

    /**
     * 清掉历史更新包。DownloadManager 不会覆盖已存在的目标文件：若沿用同名目标，
     * 下载会静默失败，通知栏里残留的旧通知被点开就会安装旧包，系统报「已存在更高版本」。
     */
    private fun purgeStaleApks(keep: String? = null) {
        val dir = getExternalFilesDir(null) ?: return
        dir.listFiles()?.forEach { f ->
            if (f.name.startsWith("see-update") && f.name.endsWith(".apk") && f.name != keep) {
                try { f.delete() } catch (_: Exception) {}
            }
        }
    }

    private fun downloadAndInstall(ver: String, url: String, size: Long = 0L, md5: String = "") {
        // 文件名带上时间戳：DownloadManager 遇到已存在的同名目标会静默失败，
        // 之后通知栏/回调一旦点到那个半截旧包，系统就报「解析包时出现问题」。
        val dest = "see-update-" + ver.replace(Regex("[^0-9A-Za-z._-]"), "_") + "-" + System.currentTimeMillis() + ".apk"
        pendingApkName = dest
        pendingApkSize = if (size > 0) size else 0L
        pendingApkMd5 = (md5 ?: "").trim().lowercase()
        purgeStaleApks(dest)
        try {
            val request = android.app.DownloadManager.Request(android.net.Uri.parse(url))
            request.setTitle("see 更新 v" + ver)
            request.setMimeType("application/vnd.android.package-archive")
            request.addRequestHeader("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
            request.setNotificationVisibility(android.app.DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
            request.setDestinationInExternalFilesDir(this, null, dest)
            val dm = getSystemService(DOWNLOAD_SERVICE) as android.app.DownloadManager
            updateDownloadId = dm.enqueue(request)
        } catch (e: Exception) {
            try { startActivity(android.content.Intent(android.content.Intent.ACTION_VIEW, android.net.Uri.parse(url))) } catch (_: Exception) {}
        }
    }

    private fun openDownloadedApk() {
        try {
            // 先看 DownloadManager 自己的结论：没下成功就别把半截包丢给安装器。
            var status = -1
            try {
                val dm = getSystemService(DOWNLOAD_SERVICE) as android.app.DownloadManager
                dm.query(android.app.DownloadManager.Query().setFilterById(updateDownloadId))?.use { c ->
                    if (c.moveToFirst()) status = c.getInt(c.getColumnIndexOrThrow(android.app.DownloadManager.COLUMN_STATUS))
                }
            } catch (_: Exception) {}
            if (status != android.app.DownloadManager.STATUS_SUCCESSFUL) {
                toast("下载没完成，请稍后重试")
                return
            }
            val dir = getExternalFilesDir(null) ?: return
            val file = (pendingApkName?.let { java.io.File(dir, it) })?.takeIf { it.exists() }
                ?: dir.listFiles()?.filter { it.name.startsWith("see-update") && it.name.endsWith(".apk") }
                    ?.maxByOrNull { it.lastModified() }
            if (file == null || !file.exists()) return
            // 再自己验一遍：大小 + md5（拿不到就只验大小）。不匹配就删掉重下，
            // 否则系统安装器会直接报「解包/解析包时出现问题」。
            if (pendingApkSize > 0 && file.length() != pendingApkSize) {
                try { file.delete() } catch (_: Exception) {}
                toast("安装包不完整（" + file.length() + "/" + pendingApkSize + " 字节），已删除，请重新下载")
                return
            }
            if (pendingApkMd5.isNotEmpty()) {
                val got = md5Of(file)
                if (got.isNotEmpty() && got != pendingApkMd5) {
                    try { file.delete() } catch (_: Exception) {}
                    toast("安装包校验不通过（md5 不符），已删除，请重新下载")
                    return
                }
            }
            val uri = androidx.core.content.FileProvider.getUriForFile(this, "$packageName.fileprovider", file)
            val install = android.content.Intent(android.content.Intent.ACTION_VIEW)
            install.setDataAndType(uri, "application/vnd.android.package-archive")
            install.addFlags(android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION)
            install.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
            notifyInstall(install)
            try { startActivity(install) } catch (_: Exception) {}
        } catch (e: Exception) { e.printStackTrace() }
    }

    private fun notifyInstall(install: android.content.Intent) {
        try {
            val channelId = "see_update"
            val nm = getSystemService(NOTIFICATION_SERVICE) as android.app.NotificationManager
            if (android.os.Build.VERSION.SDK_INT >= 26) {
                nm.createNotificationChannel(android.app.NotificationChannel(channelId, "版本更新", android.app.NotificationManager.IMPORTANCE_HIGH))
            }
            val pi = android.app.PendingIntent.getActivity(this, 1, install,
                android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE)
            val nb = android.app.Notification.Builder(this, channelId)
                .setSmallIcon(android.R.drawable.stat_sys_download_done)
                .setContentTitle("see 更新已下载")
                .setContentText("点击此处安装新版本")
                .setContentIntent(pi)
                .setAutoCancel(true)
            nm.notify(2001, nb.build())
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
        server = SeeServer(this, scanner, localIp(), db)
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
        web.setDownloadListener { url, _, contentDisposition, mimeType, _ ->
            try {
                val name = android.webkit.URLUtil.guessFileName(url, contentDisposition, mimeType)
                val isApk = name.endsWith(".apk", true)
                val request = android.app.DownloadManager.Request(android.net.Uri.parse(url))
                request.setMimeType(mimeType)
                request.setTitle(name)
                request.addRequestHeader("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
                request.setNotificationVisibility(android.app.DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
                if (isApk) {
                    val dest = "see-update-" + System.currentTimeMillis() + ".apk"
                    pendingApkName = dest
                    purgeStaleApks(dest)
                    request.setDestinationInExternalFilesDir(this, null, dest)
                } else {
                    request.setDestinationInExternalPublicDir(android.os.Environment.DIRECTORY_DOWNLOADS, name)
                }
                val dm = getSystemService(DOWNLOAD_SERVICE) as android.app.DownloadManager
                val id = dm.enqueue(request)
                if (isApk) updateDownloadId = id
            } catch (e: Exception) {
                try { startActivity(android.content.Intent(android.content.Intent.ACTION_VIEW, android.net.Uri.parse(url))) } catch (_: Exception) {}
            }
        }
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
                                "<h2>see v2.90</h2><p>本机服务连接失败</p>" +
                                "<p style='color:#b02a37;font-size:13px'>" + msg + "</p>" +
                                "<p style='font-size:12px;color:#666'>点返回键或重新打开应用重试</p></body></html>",
                                "text/html", "utf-8", null)
                        }, 600)
                    }
                }
            }
        }
        setContentView(web)
        if (android.os.Build.VERSION.SDK_INT >= 33 && checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 2003)
        }
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

    /**
     * 局域网（WiFi / 有线）这一层的链路信息。
     *
     * 不能用 activeNetwork：手机上挂了 VPN / 代理（tun）时，系统把 VPN 当成默认网络，
     * activeNetwork 会指向 tun 接口（地址形如 172.19.0.2/24），于是「本机IP / 网段 / 网关」
     * 全被算成隧道那张网 —— 观察页就会去扫 172.19.0.0/24，并把真正的局域网设备当成「网段外」丢掉。
     * 观察页只关心手机所在的那层局域网，所以优先取 WiFi / 有线网络；取不到再退回 activeNetwork。
     */
    private fun lanLink(): android.net.LinkProperties? {
        return try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            for (n in cm.allNetworks) {
                val nc = cm.getNetworkCapabilities(n) ?: continue
                if (nc.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) || nc.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
                    val lp = cm.getLinkProperties(n)
                    if (lp != null) return lp
                }
            }
            null
        } catch (_: Exception) { null }
    }

    private fun linkProps(): android.net.LinkProperties? {
        return try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            lanLink() ?: cm.getLinkProperties(cm.activeNetwork)
        } catch (_: Exception) { null }
    }

    private fun gwIp(): String {
        return try {
            val lp = linkProps() ?: return ""
            for (r in lp.routes) {
                val g = r.gateway?.hostAddress
                if (!g.isNullOrEmpty()) return g
            }
            ""
        } catch (_: Exception) { "" }
    }

    private fun ipInfo(): Pair<String, Int>? {
        return try {
            val lp = linkProps() ?: return null
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
        if (chartFs) {                       // 先退图表全屏，别直接退应用
            web.evaluateJavascript("window.seeExitChartFs&&seeExitChartFs()", null)
            return
        }
        if (web.canGoBack()) web.goBack() else super.onBackPressed()
    }
}
