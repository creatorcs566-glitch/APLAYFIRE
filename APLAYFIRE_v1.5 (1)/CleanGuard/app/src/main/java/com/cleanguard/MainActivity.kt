package com.cleanguard

import android.annotation.SuppressLint
import android.app.Activity
import android.app.ActivityManager
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.PowerManager
import android.os.StatFs
import android.provider.Settings
import android.util.Base64
import android.view.View
import android.webkit.JavascriptInterface
import android.webkit.WebView
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File

class MainActivity : Activity() {
    private lateinit var web: WebView
    private var junk: List<File> = emptyList()
    private var hits: List<Hit> = emptyList()
    private val uq = ArrayDeque<String>()
    private var prevFilter = -1

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = Color.WHITE
        if (Build.VERSION.SDK_INT >= 23) window.decorView.systemUiVisibility = View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != PackageManager.PERMISSION_GRANTED)
            requestPermissions(arrayOf("android.permission.POST_NOTIFICATIONS"), 2)
        web = WebView(this)
        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        web.addJavascriptInterface(Bridge(), "Android")
        web.loadUrl("file:///android_asset/index.html")
        setContentView(web)
        if (ThreatLog.enabled(this) && storageOk()) ProtectionService.start(this)
        if (ThreatLog.setting(this, "web", false) && VpnService.prepare(this) == null) WebGuardService.start(this)
    }

    override fun onResume() {
        super.onResume()
        if (::web.isInitialized) emit("prot", Bridge().protection())
    }

    override fun onActivityResult(req: Int, res: Int, d: Intent?) {
        super.onActivityResult(req, res, d)
        if (req == 7 && res == RESULT_OK) WebGuardService.start(this)
        if (req == 9) nextUninstall()
        emit("prot", Bridge().protection())
    }

    private fun nextUninstall() {
        val p = uq.removeFirstOrNull() ?: return
        Remover.kill(this, p)
        startActivityForResult(Intent(Intent.ACTION_DELETE, Uri.parse("package:$p")).putExtra(Intent.EXTRA_RETURN_RESULT, true), 9)
    }

    private fun emit(type: String, json: Any) = runOnUiThread { web.evaluateJavascript("onNative('$type',$json)", null) }

    private fun storageOk(): Boolean = if (Build.VERSION.SDK_INT >= 30) Environment.isExternalStorageManager()
        else checkSelfPermission(android.Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED

    private fun hasAccess(): Boolean {
        if (storageOk()) return true
        if (Build.VERSION.SDK_INT >= 30) startActivity(Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:$packageName")))
        else requestPermissions(arrayOf(android.Manifest.permission.WRITE_EXTERNAL_STORAGE), 1)
        return false
    }

    private fun isGame(a: ApplicationInfo) = (Build.VERSION.SDK_INT >= 26 && a.category == ApplicationInfo.CATEGORY_GAME) || (a.flags and 0x2000000) != 0

    inner class Bridge {
        @JavascriptInterface fun status(): String {
            val am = getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
            val mi = ActivityManager.MemoryInfo().also { am.getMemoryInfo(it) }
            val st = StatFs(Environment.getDataDirectory().path)
            return JSONObject().put("rt", mi.totalMem).put("rf", mi.availMem).put("st", st.totalBytes)
                .put("sf", st.availableBytes).put("v", Build.VERSION.RELEASE).toString()
        }

        // ---- verificação profunda ----
        @JavascriptInterface fun deepScan() {
            runOnUiThread {
                if (!hasAccess()) { emit("perm", "{}"); return@runOnUiThread }
                Thread {
                    val t0 = System.currentTimeMillis()
                    hits = DeepScan.run(this@MainActivity) { emit("deep", it) }
                    val auto = ThreatLog.setting(this@MainActivity, "auto", true)
                    val res = JSONArray()
                    val apps = mutableListOf<String>()
                    hits.forEach { h ->
                        ThreatLog.add(this@MainActivity, h.kind, h.name, h.target, h.level, h.reasons)
                        var st = "none"
                        if (auto && h.level >= 2 && h.kind != "sys") {
                            if (h.kind == "file") st = if (Remover.file(h.target) == "ok") "removed" else "failed"
                            else { apps += h.target; st = "pending" }
                        }
                        res.put(JSONObject().put("k", h.kind).put("n", h.name).put("p", h.target).put("l", h.level)
                            .put("w", JSONArray(h.reasons)).put("st", st))
                    }
                    emit("deepdone", JSONObject().put("hits", res).put("files", DeepScan.files).put("s", (System.currentTimeMillis() - t0) / 1000))
                    if (apps.isNotEmpty()) web.postDelayed({ uq.addAll(apps); nextUninstall() }, 1800)
                }.start()
            }
        }
        @JavascriptInterface fun deepCancel() { DeepScan.cancel = true }
        @JavascriptInterface fun removeAll() {
            Thread {
                val res = JSONArray()
                val apps = mutableListOf<String>()
                hits.forEach { h ->
                    if (h.kind == "file") res.put(JSONObject().put("p", h.target).put("st", if (Remover.file(h.target) == "ok") "removed" else "failed"))
                    else if (h.kind == "app") { apps += h.target; res.put(JSONObject().put("p", h.target).put("st", "pending")) }
                }
                emit("removed", JSONObject().put("res", res))
                if (apps.isNotEmpty()) runOnUiThread { uq.addAll(apps); nextUninstall() }
            }.start()
        }

        // ---- limpeza ----
        @JavascriptInterface fun findJunk() {
            runOnUiThread {
                if (!hasAccess()) { emit("perm", "{}"); return@runOnUiThread }
                Thread {
                    junk = Cleaner.findJunk()
                    emit("junk", JSONObject().put("c", junk.size).put("b", junk.sumOf { it.length() })
                        .put("f", JSONArray(junk.take(5).map { it.path })))
                }.start()
            }
        }
        @JavascriptInterface fun clean() {
            Thread {
                val freed = Cleaner.delete(junk) + Cleaner.clearOwnCache(this@MainActivity)
                junk = emptyList()
                emit("clean", JSONObject().put("b", freed))
            }.start()
        }

        // ---- proteção ----
        @JavascriptInterface fun protection(): String = ThreatLog.json(this@MainActivity)
            .put("sigs", Scanner.blocklist(this@MainActivity).size)
            .put("ov", Settings.canDrawOverlays(this@MainActivity))
            .put("web", ThreatLog.setting(this@MainActivity, "web", false) && WebGuardService.running).toString()
        @JavascriptInterface fun setProtection(on: Boolean) {
            runOnUiThread {
                if (!on) { stopService(Intent(this@MainActivity, ProtectionService::class.java)); ThreatLog.setEnabled(this@MainActivity, false) }
                else if (!hasAccess()) emit("perm", "{}")
                else { ThreatLog.setEnabled(this@MainActivity, true); ProtectionService.start(this@MainActivity) }
                emit("prot", protection())
            }
        }
        @JavascriptInterface fun setWeb(on: Boolean) {
            runOnUiThread {
                ThreatLog.setSetting(this@MainActivity, "web", on)
                if (!on) stopService(Intent(this@MainActivity, WebGuardService::class.java))
                else { val i = VpnService.prepare(this@MainActivity); if (i != null) startActivityForResult(i, 7) else WebGuardService.start(this@MainActivity) }
                web.postDelayed({ emit("prot", protection()) }, 600)
            }
        }
        @JavascriptInterface fun overlaySettings() {
            startActivity(Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, Uri.parse("package:$packageName")))
        }
        @JavascriptInterface fun updateSigs() { Thread { emit("sigs", JSONObject().put("n", SignatureUpdater.update(this@MainActivity))) }.start() }
        @JavascriptInterface fun del(path: String): Boolean { val ok = Guard.safeDelete(path); emit("prot", protection()); return ok }
        @JavascriptInterface fun uninstall(pkg: String) { Remover.app(this@MainActivity, pkg) }

        // ---- configurações ----
        @JavascriptInterface fun settings(): String {
            val o = JSONObject()
            for (k in listOf("boot", "sigs", "auto", "f_Download", "f_Documents", "f_Telegram", "f_Bluetooth"))
                o.put(k, ThreatLog.setting(this@MainActivity, k, true))
            return o.toString()
        }
        @JavascriptInterface fun setSetting(k: String, v: Boolean) {
            ThreatLog.setSetting(this@MainActivity, k, v)
            if (k.startsWith("f_") && ThreatLog.enabled(this@MainActivity) && storageOk()) {
                stopService(Intent(this@MainActivity, ProtectionService::class.java)); ProtectionService.start(this@MainActivity)
            }
        }
        @JavascriptInterface fun setLang(l: String) { ThreatLog.setLang(this@MainActivity, l) }
        @JavascriptInterface fun clearLog() { ThreatLog.clear(this@MainActivity); emit("prot", protection()) }
        @JavascriptInterface fun setBar(hex: String, light: Boolean) {
            runOnUiThread {
                try { window.statusBarColor = Color.parseColor(hex) } catch (_: Exception) {}
                if (Build.VERSION.SDK_INT >= 23) window.decorView.systemUiVisibility = if (light) View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR else 0
            }
        }

        // ---- modo gamer ----
        @JavascriptInterface fun games(): String {
            val pm = packageManager
            @Suppress("DEPRECATION")
            val l = pm.queryIntentActivities(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER), 0)
                .map { it.activityInfo.applicationInfo }.distinctBy { it.packageName }.filter { it.packageName != packageName }
            val arr = JSONArray()
            l.sortedWith(compareByDescending<ApplicationInfo> { isGame(it) }.thenBy { pm.getApplicationLabel(it).toString().lowercase() })
                .take(250).forEach { arr.put(JSONObject().put("n", pm.getApplicationLabel(it).toString()).put("p", it.packageName).put("g", isGame(it))) }
            return arr.toString()
        }
        @JavascriptInterface fun gamerProfile(): String {
            val am = getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
            val mi = ActivityManager.MemoryInfo().also { am.getMemoryInfo(it) }
            val gb = mi.totalMem / 1073741824.0
            val pw = getSystemService(PowerManager::class.java)
            return JSONObject().put("tier", if (gb <= 3.6) 0 else if (gb <= 6.6) 1 else 2).put("rt", mi.totalMem).put("rf", mi.availMem)
                .put("th", if (Build.VERSION.SDK_INT >= 29) pw.currentThermalStatus else 0).put("ps", pw.isPowerSaveMode)
                .put("dnd", getSystemService(NotificationManager::class.java).isNotificationPolicyAccessGranted).toString()
        }
        @JavascriptInterface fun gamerStart(pkg: String, kill: Boolean, dnd: Boolean, clean: Boolean) {
            Thread {
                val am = getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
                fun free() = ActivityManager.MemoryInfo().also { am.getMemoryInfo(it) }.availMem
                val before = free()
                var killed = 0; var needDnd = false; var dndOn = false
                if (dnd) {
                    val nm = getSystemService(NotificationManager::class.java)
                    if (nm.isNotificationPolicyAccessGranted) {
                        prevFilter = nm.currentInterruptionFilter
                        nm.setInterruptionFilter(NotificationManager.INTERRUPTION_FILTER_ALARMS); dndOn = true
                    } else needDnd = true
                }
                if (kill) {
                    @Suppress("DEPRECATION")
                    for (a in packageManager.getInstalledApplications(0)) {
                        if (a.flags and ApplicationInfo.FLAG_SYSTEM != 0 || a.packageName == packageName || a.packageName == pkg) continue
                        Remover.kill(this@MainActivity, a.packageName); killed++
                    }
                }
                if (clean) Cleaner.clearOwnCache(this@MainActivity)
                Thread.sleep(1000)
                emit("gamer", JSONObject().put("before", before).put("after", free()).put("killed", killed).put("dnd", dndOn).put("needDnd", needDnd))
            }.start()
        }
        @JavascriptInterface fun gamerStop() {
            if (prevFilter >= 0) try { getSystemService(NotificationManager::class.java).setInterruptionFilter(prevFilter) } catch (_: Exception) {}
            prevFilter = -1
        }
        @JavascriptInterface fun loadIcons(json: String) {
            Thread {
                val a = JSONArray(json)
                for (i in 0 until a.length()) {
                    val p = a.getString(i)
                    try {
                        val d = packageManager.getApplicationIcon(p)
                        val bm = Bitmap.createBitmap(96, 96, Bitmap.Config.ARGB_8888)
                        d.setBounds(0, 0, 96, 96); d.draw(Canvas(bm))
                        val o = ByteArrayOutputStream(); bm.compress(Bitmap.CompressFormat.PNG, 100, o)
                        emit("icon", JSONObject().put("p", p).put("d", "data:image/png;base64," + Base64.encodeToString(o.toByteArray(), Base64.NO_WRAP)))
                    } catch (_: Exception) {}
                }
            }.start()
        }
        @JavascriptInterface fun openUrl(u: String) { if (u.startsWith("https://")) runOnUiThread { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(u))) } }
        @JavascriptInterface fun launch(pkg: String) { runOnUiThread { packageManager.getLaunchIntentForPackage(pkg)?.let { startActivity(it) } } }
        @JavascriptInterface fun dndSettings() { startActivity(Intent(Settings.ACTION_NOTIFICATION_POLICY_ACCESS_SETTINGS)) }
    }
}
