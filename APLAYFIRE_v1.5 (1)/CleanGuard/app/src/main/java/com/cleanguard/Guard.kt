package com.cleanguard

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.drawable.Icon
import android.net.Uri
import android.os.Build
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.URL
import javax.net.ssl.HttpsURLConnection

object ThreatLog {
    private fun sp(c: Context) = c.getSharedPreferences("guard", Context.MODE_PRIVATE)
    fun enabled(c: Context) = sp(c).getBoolean("on", false)
    fun setEnabled(c: Context, v: Boolean) = sp(c).edit().putBoolean("on", v).apply()
    fun setting(c: Context, k: String, d: Boolean) = sp(c).getBoolean("s_$k", d)
    fun setSetting(c: Context, k: String, v: Boolean) = sp(c).edit().putBoolean("s_$k", v).apply()
    fun lang(c: Context): String = sp(c).getString("lang", "pt") ?: "pt"
    fun setLang(c: Context, l: String) = sp(c).edit().putString("lang", l).apply()
    fun clear(c: Context) = sp(c).edit().putString("log", "[]").putInt("threats", 0).apply()
    fun allowed(c: Context, k: String) = sp(c).getStringSet("allow", emptySet())!!.contains(k)
    fun allow(c: Context, k: String) = sp(c).edit().putStringSet("allow", HashSet(sp(c).getStringSet("allow", emptySet())!!) + k).apply()
    @Synchronized fun checked(c: Context) = sp(c).edit().putInt("files", sp(c).getInt("files", 0) + 1).apply()
    @Synchronized fun add(c: Context, kind: String, name: String, target: String, level: Int, reasons: List<String>) {
        val o = JSONObject().put("t", System.currentTimeMillis()).put("k", kind).put("n", name)
            .put("p", target).put("l", level).put("w", JSONArray(reasons))
        val old = JSONArray(sp(c).getString("log", "[]"))
        val arr = JSONArray().put(o)
        for (i in 0 until minOf(old.length(), 49)) arr.put(old.get(i))
        sp(c).edit().putString("log", arr.toString()).putInt("threats", sp(c).getInt("threats", 0) + 1).apply()
    }
    fun json(c: Context): JSONObject = JSONObject().put("on", enabled(c)).put("files", sp(c).getInt("files", 0))
        .put("threats", sp(c).getInt("threats", 0)).put("ev", JSONArray(sp(c).getString("log", "[]")))
}

object Tr {
    private fun e(pt: String, en: String, es: String) = pt to listOf(pt, en, es)
    private val M = mapOf(
        e("Download perigoso: ", "Dangerous download: ", "Descarga peligrosa: "),
        e("Download suspeito: ", "Suspicious download: ", "Descarga sospechosa: "),
        e("App suspeito instalado: ", "Suspicious app installed: ", "App sospechosa instalada: "),
        e("Ameaça removida: ", "Threat removed: ", "Amenaza eliminada: "),
        e("Apagar arquivo", "Delete file", "Borrar archivo"),
        e("Desinstalar", "Uninstall", "Desinstalar"),
        e("Alertas de ameaça", "Threat alerts", "Alertas de amenazas"),
        e("Proteção ativa", "Active protection", "Protección activa"),
        e("APLAYFIRE protegendo", "APLAYFIRE is protecting", "APLAYFIRE protegiendo"),
        e("Vigiando downloads e novos apps", "Watching downloads and new apps", "Vigilando descargas y apps nuevas"),
        e("Assinatura (hash) conhecida de malware", "Known malware signature (hash)", "Firma (hash) conocida de malware"),
        e("Extensão dupla enganosa (disfarçado de documento ou mídia)", "Deceptive double extension (disguised as a document or media)", "Doble extensión engañosa (disfrazado de documento o medio)"),
        e("Arquivo executável incomum em celular", "Unusual executable file on a phone", "Archivo ejecutable inusual en un móvil"),
        e("Executável disfarçado: o conteúdo não corresponde à extensão", "Disguised executable: content does not match the extension", "Ejecutable disfrazado: el contenido no coincide con la extensión"),
        e("APK fora da loja: instale apenas de fontes confiáveis", "APK outside the store: install only from trusted sources", "APK fuera de la tienda: instala solo de fuentes confiables"),
        e("Arquivo de teste EICAR (inofensivo, usado para testar antivírus)", "EICAR test file (harmless, used to test antivirus)", "Archivo de prueba EICAR (inofensivo, para probar antivirus)"),
        e("Nome imita um app conhecido ({})", "Name imitates a known app ({})", "El nombre imita una app conocida ({})"),
        e("App sem ícone de abertura (oculto) instalado fora de loja confiável", "Hidden app (no launcher icon) installed outside a trusted store", "App oculta (sin ícono) instalada fuera de una tienda confiable"),
        e("Depuração USB (ADB) ativada", "USB debugging (ADB) is on", "Depuración USB (ADB) activada"),
        e("Domínio na lista de ameaças", "Domain on the threat list", "Dominio en la lista de amenazas"),
        e("Endereço com caracteres disfarçados (punycode)", "Address with disguised characters (punycode)", "Dirección con caracteres disfrazados (punycode)"),
        e("Extensão de domínio muito usada em golpes", "Domain extension often used in scams", "Extensión de dominio muy usada en estafas"),
        e("Imita a marca {}", "Imitates the brand {}", "Imita la marca {}"),
        e("Endereço com muitos hifens", "Address with many hyphens", "Dirección con muchos guiones"),
        e("Bloqueado pelo filtro de ameaças (Cloudflare)", "Blocked by threat filter (Cloudflare)", "Bloqueado por el filtro de amenazas (Cloudflare)"))
    fun t(c: Context, k: String): String {
        val i = when (ThreatLog.lang(c)) { "en" -> 1; "es" -> 2; else -> 0 }
        return M[k]?.get(i) ?: k
    }
}

object Notifier {
    private const val CH = "guard"
    private const val CH2 = "status"
    fun channels(c: Context) {
        if (Build.VERSION.SDK_INT < 26) return
        val nm = c.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CH, Tr.t(c, "Alertas de ameaça"), NotificationManager.IMPORTANCE_HIGH))
        nm.createNotificationChannel(NotificationChannel(CH2, Tr.t(c, "Proteção ativa"), NotificationManager.IMPORTANCE_MIN))
    }
    @Suppress("DEPRECATION")
    private fun builder(c: Context, ch: String): Notification.Builder =
        if (Build.VERSION.SDK_INT >= 26) Notification.Builder(c, ch) else Notification.Builder(c)
    private fun open(c: Context) = PendingIntent.getActivity(c, 0, Intent(c, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
    fun ongoing(c: Context): Notification = builder(c, CH2).setSmallIcon(android.R.drawable.ic_lock_idle_lock)
        .setContentTitle(Tr.t(c, "APLAYFIRE protegendo")).setContentText(Tr.t(c, "Vigiando downloads e novos apps"))
        .setContentIntent(open(c)).setOngoing(true).build()
    fun threat(c: Context, id: Int, title: String, text: String, action: Notification.Action?) {
        val b = builder(c, CH).setSmallIcon(android.R.drawable.stat_sys_warning).setContentTitle(title)
            .setContentText(text.lines().first()).setStyle(Notification.BigTextStyle().bigText(text))
            .setContentIntent(open(c)).setAutoCancel(true)
        action?.let { b.addAction(it) }
        try { c.getSystemService(NotificationManager::class.java).notify(id, b.build()) } catch (_: Exception) {}
    }
    fun deleteAction(c: Context, path: String, id: Int): Notification.Action {
        val i = Intent(c, ActionReceiver::class.java).putExtra("path", path).putExtra("id", id)
        val pi = PendingIntent.getBroadcast(c, id, i, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        return Notification.Action.Builder(Icon.createWithResource(c, android.R.drawable.ic_menu_delete), Tr.t(c, "Apagar arquivo"), pi).build()
    }
    fun uninstallAction(c: Context, pkg: String, id: Int): Notification.Action {
        val i = Intent(Intent.ACTION_DELETE, Uri.parse("package:$pkg")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val pi = PendingIntent.getActivity(c, id, i, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        return Notification.Action.Builder(Icon.createWithResource(c, android.R.drawable.ic_menu_delete), Tr.t(c, "Desinstalar"), pi).build()
    }
}

object Guard {
    fun safeDelete(path: String): Boolean = Remover.file(path) == "ok"

    fun checkFile(c: Context, f: File) {
        if (!f.isFile || ThreatLog.allowed(c, f.path)) return
        ThreatLog.checked(c)
        val v = Scanner.analyzeFile(c, f, Scanner.blocklist(c))
        if (v.level == 0) return
        ThreatLog.add(c, "file", f.name, f.path, v.level, v.reasons)
        if (Overlay.show(c, "file", f.name, f.path, v.level, v.reasons)) return
        val id = f.path.hashCode()
        if (v.level >= 2 && ThreatLog.setting(c, "auto", true) && Remover.file(f.path) == "ok") {
            Notifier.threat(c, id, Tr.t(c, "Ameaça removida: ") + f.name, v.reasons.joinToString("\n• ", "• "), null); return
        }
        Notifier.threat(c, id, Tr.t(c, if (v.level >= 2) "Download perigoso: " else "Download suspeito: ") + f.name,
            v.reasons.joinToString("\n• ", "• "), Notifier.deleteAction(c, f.path, id))
    }

    fun checkPackage(c: Context, pkg: String) {
        try {
            if (ThreatLog.allowed(c, pkg)) return
            @Suppress("DEPRECATION")
            val p = c.packageManager.getPackageInfo(pkg, 0)
            val f = Scanner.analyzePackage(c, p, Scanner.blocklist(c)) ?: return
            val lvl = if (f.risk >= 5) 2 else 1
            ThreatLog.add(c, "app", f.label, f.pkg, lvl, f.reasons)
            if (Overlay.show(c, "app", f.label, f.pkg, lvl, f.reasons)) return
            Notifier.threat(c, pkg.hashCode(), Tr.t(c, "App suspeito instalado: ") + f.label,
                f.reasons.joinToString("\n• ", "• "), Notifier.uninstallAction(c, pkg, pkg.hashCode()))
        } catch (_: Exception) {}
    }
}

object SignatureUpdater {
    // Troque pelas URLs raw dos seus arquivos no GitHub
    const val SIG_URL = "https://raw.githubusercontent.com/SEU_USUARIO/SEU_REPO/main/blocklist.txt"
    const val DOM_URL = "https://raw.githubusercontent.com/SEU_USUARIO/SEU_REPO/main/domains.txt"
    private val HEX = Regex("[0-9a-f]{64}")
    private val DOM = Regex("[a-z0-9][a-z0-9.-]{1,200}\\.[a-z]{2,}")
    private fun fetch(c: Context, url: String, file: String, rx: Regex): Int {
        val con = URL(url).openConnection() as HttpsURLConnection
        con.connectTimeout = 10000; con.readTimeout = 15000
        val ok = con.inputStream.bufferedReader().useLines { seq ->
            seq.map { x -> x.trim().lowercase() }.filter { x -> rx.matches(x) }.take(500000).toList()
        }
        File(c.filesDir, file).writeText(ok.joinToString("\n"))
        return ok.size
    }
    fun update(c: Context): Int {
        if (SIG_URL.contains("SEU_USUARIO")) return -1
        return try {
            val n = fetch(c, SIG_URL, "blocklist.txt", HEX)
            try { fetch(c, DOM_URL, "domains.txt", DOM); WebGuard.load(c) } catch (_: Exception) {}
            n
        } catch (e: Exception) { -2 }
    }
}
