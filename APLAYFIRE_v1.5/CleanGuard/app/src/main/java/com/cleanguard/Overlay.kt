package com.cleanguard

import android.content.Context
import android.content.Intent
import android.graphics.PixelFormat
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.WindowManager
import android.webkit.JavascriptInterface
import android.webkit.WebView
import android.webkit.WebViewClient
import org.json.JSONArray
import org.json.JSONObject

// Tela de bloqueio em tela cheia, desenhada sobre qualquer app (precisa da permissão "Exibir sobre outros apps").
object Overlay {
    private val h = Handler(Looper.getMainLooper())
    private var view: WebView? = null

    fun show(c: Context, kind: String, name: String, target: String, level: Int, reasons: List<String>): Boolean {
        if (!Settings.canDrawOverlays(c)) return false
        val app = c.applicationContext
        h.post {
            if (view != null) return@post
            try {
                val wm = app.getSystemService(Context.WINDOW_SERVICE) as WindowManager
                val w = WebView(app)
                w.settings.javaScriptEnabled = true
                w.addJavascriptInterface(Br(app, kind, target), "Blk")
                val data = JSONObject().put("kind", kind).put("name", name).put("level", level)
                    .put("w", JSONArray(reasons)).put("lang", ThreatLog.lang(app))
                w.webViewClient = object : WebViewClient() {
                    override fun onPageFinished(v: WebView, u: String) { v.evaluateJavascript("init($data)", null) }
                }
                w.loadUrl("file:///android_asset/block.html")
                val type = if (Build.VERSION.SDK_INT >= 26) WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
                           else @Suppress("DEPRECATION") WindowManager.LayoutParams.TYPE_PHONE
                val lp = WindowManager.LayoutParams(-1, -1, type,
                    WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN or WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS,
                    PixelFormat.TRANSLUCENT)
                wm.addView(w, lp)
                view = w
            } catch (_: Exception) { view = null }
        }
        return true
    }

    private fun close(c: Context) {
        h.post {
            view?.let { try { (c.getSystemService(Context.WINDOW_SERVICE) as WindowManager).removeView(it); it.destroy() } catch (_: Exception) {} }
            view = null
        }
    }

    class Br(private val c: Context, private val kind: String, private val target: String) {
        @JavascriptInterface fun deny() {
            Thread { when (kind) { "file" -> Remover.file(target); "app" -> Remover.app(c, target) }; close(c) }.start()
        }
        @JavascriptInterface fun allow() {
            Thread {
                if (kind == "web") {
                    WebGuardService.allow(target)
                    try { c.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://$target")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) } catch (_: Exception) {}
                } else ThreatLog.allow(c, target)
                close(c)
            }.start()
        }
    }
}
