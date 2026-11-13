package com.cleanguard

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.StatFs
import android.provider.Settings
import org.json.JSONObject
import java.io.File
import java.io.RandomAccessFile

data class Hit(val kind: String, val name: String, val target: String, val level: Int, val reasons: List<String>)

object Remover {
    // Escada de remoção: apagar, esvaziar e apagar, renomear e apagar, forçar permissão.
    fun file(path: String): String {
        val f = File(path)
        try { if (!f.canonicalPath.startsWith(Environment.getExternalStorageDirectory().canonicalPath)) return "fail" } catch (_: Exception) { return "fail" }
        if (!f.exists()) return "ok"
        if (f.isDirectory) { f.deleteRecursively() } else {
            if (f.delete()) return "ok"
            try { RandomAccessFile(f, "rw").use { it.setLength(0) } } catch (_: Exception) {}
            if (f.delete()) return "ok"
            try { val r = File(f.parentFile, ".rm" + System.nanoTime()); if (f.renameTo(r)) r.delete() } catch (_: Exception) {}
            try { f.setWritable(true, false); f.delete() } catch (_: Exception) {}
        }
        return if (f.exists()) "fail" else "ok"
    }
    fun kill(c: Context, pkg: String) {
        try { (c.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager).killBackgroundProcesses(pkg) } catch (_: Exception) {}
    }
    // O Android exige confirmação do usuário para desinstalar (sem root/dono do dispositivo).
    fun app(c: Context, pkg: String) {
        kill(c, pkg)
        try { c.startActivity(Intent(Intent.ACTION_DELETE, Uri.parse("package:$pkg")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) } catch (_: Exception) {}
    }
}

object DeepScan {
    @Volatile var cancel = false
    @Volatile var files = 0

    fun run(ctx: Context, cb: (JSONObject) -> Unit): List<Hit> {
        cancel = false; files = 0
        val bl = Scanner.blocklist(ctx)
        val hits = mutableListOf<Hit>()
        fun prog(st: Int, p: Int, cur: String = "", a: Int = 0, b: Int = 0) =
            cb(JSONObject().put("st", st).put("p", p).put("cur", cur).put("n", files).put("a", a).put("b", b))
        @Suppress("DEPRECATION")
        val apps = ctx.packageManager.getInstalledPackages(0)
        apps.forEachIndexed { i, p ->
            if (cancel) return@forEachIndexed
            Scanner.analyzePackage(ctx, p, bl)?.let { f -> hits += Hit("app", f.label, f.pkg, if (f.risk >= 5) 2 else 1, f.reasons) }
            if (i % 4 == 0) prog(0, (i + 1) * 100 / maxOf(1, apps.size), p.packageName, i + 1, apps.size)
        }
        prog(0, 100, "", apps.size, apps.size)
        val root = Environment.getExternalStorageDirectory()
        val st = StatFs(root.path)
        val used = maxOf(1L, st.totalBytes - st.availableBytes)
        var bytes = 0L
        val stack = ArrayDeque<File>()
        stack.add(root)
        while (stack.isNotEmpty() && !cancel) {
            val d = stack.removeLast()
            val kids = d.listFiles() ?: continue
            for (f in kids) {
                if (cancel) break
                if (f.isDirectory) {
                    val rel = f.path.removePrefix(root.path)
                    if (rel == "/Android/data" || rel == "/Android/obb") continue
                    if (Build.VERSION.SDK_INT >= 26 && java.nio.file.Files.isSymbolicLink(f.toPath())) continue
                    stack.add(f)
                } else {
                    files++; bytes += f.length()
                    val v = Scanner.analyzeFile(ctx, f, bl, true)
                    if (v.level > 0) hits += Hit("file", f.name, f.path, v.level, v.reasons)
                    if (files % 150 == 0) prog(1, minOf(99, (bytes * 100 / used).toInt()), f.path)
                }
            }
        }
        prog(1, 100)
        if (!cancel) {
            try {
                if (Settings.Global.getInt(ctx.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1)
                    hits += Hit("sys", "ADB", "adb", 1, listOf(Tr.t(ctx, "Depuração USB (ADB) ativada")))
            } catch (_: Exception) {}
            prog(2, 100)
        }
        return hits
    }
}
