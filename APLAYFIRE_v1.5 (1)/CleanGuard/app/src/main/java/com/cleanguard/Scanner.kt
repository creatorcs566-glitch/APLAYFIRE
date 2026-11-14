package com.cleanguard

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.os.Build
import java.io.File
import java.security.MessageDigest

data class Finding(val pkg: String, val label: String, val risk: Int, val reasons: List<String>)
data class Verdict(val level: Int, val reasons: List<String>)

object Scanner {
    private val TRUSTED = setOf("com.android.vending", "com.sec.android.app.samsungapps",
        "com.huawei.appmarket", "com.amazon.venezia", "com.xiaomi.mipicks")
    private const val EICAR = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    private val BAD_EXT = setOf("exe", "scr", "bat", "cmd", "vbs", "js", "jar", "msi", "com", "pif", "lnk")
    private val HASH_EXT = BAD_EXT + setOf("apk", "dex", "so", "sh")
    private val MEDIA_EXT = setOf("jpg", "jpeg", "png", "gif", "webp", "bmp", "mp3", "mp4", "m4a", "wav", "pdf", "doc", "docx", "xls", "xlsx", "txt", "mkv", "avi")
    private val DOUBLE = Regex(".*\\.(jpe?g|png|gif|pdf|docx?|xlsx?|pptx?|txt|mp3|mp4|zip|rar)\\.(apk|exe|scr|bat|cmd|vbs|js|jar|lnk)$")
    private val BRANDS = mapOf("whatsapp" to listOf("com.whatsapp"), "instagram" to listOf("com.instagram"),
        "facebook" to listOf("com.facebook"), "telegram" to listOf("org.telegram"),
        "tiktok" to listOf("com.zhiliaoapp", "com.ss.android"), "nubank" to listOf("com.nu."),
        "free fire" to listOf("com.dts."), "youtube" to listOf("com.google.android.youtube"),
        "netflix" to listOf("com.netflix"), "paypal" to listOf("com.paypal"))

    fun sha256(f: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        f.inputStream().use { s ->
            val buf = ByteArray(8192)
            while (true) { val n = s.read(buf); if (n < 0) break; md.update(buf, 0, n) }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    fun blocklist(ctx: Context): Set<String> {
        val out = HashSet<String>()
        fun add(lines: List<String>) { for (l in lines) { val t = l.trim().lowercase(); if (t.isNotEmpty() && !t.startsWith("#")) out += t } }
        try { add(ctx.assets.open("blocklist.txt").bufferedReader().readLines()) } catch (_: Exception) {}
        try { val f = File(ctx.filesDir, "blocklist.txt"); if (f.exists()) add(f.readLines()) } catch (_: Exception) {}
        return out
    }

    private fun installer(ctx: Context, pkg: String): String? = try {
        if (Build.VERSION.SDK_INT >= 30) ctx.packageManager.getInstallSourceInfo(pkg).installingPackageName
        else @Suppress("DEPRECATION") ctx.packageManager.getInstallerPackageName(pkg)
    } catch (e: Exception) { null }

    private fun impersonates(label: String, pkg: String): String? {
        val l = label.lowercase().trim()
        for ((b, pre) in BRANDS) if (l.startsWith(b) && pre.none { pkg.startsWith(it) }) return b
        return null
    }

    // Permissões NÃO contam como risco. Avalia: hash, imitação de marca, app oculto fora de loja.
    fun analyzePackage(ctx: Context, p: PackageInfo, bl: Set<String>): Finding? {
        val ai = p.applicationInfo ?: return null
        if (ai.flags and ApplicationInfo.FLAG_SYSTEM != 0 || p.packageName == ctx.packageName) return null
        var risk = 0
        val r = mutableListOf<String>()
        try { if (sha256(File(ai.sourceDir)) in bl) { risk += 10; r += Tr.t(ctx, "Assinatura (hash) conhecida de malware") } } catch (_: Exception) {}
        val label = ctx.packageManager.getApplicationLabel(ai).toString()
        if (installer(ctx, p.packageName) !in TRUSTED) {
            impersonates(label, p.packageName)?.let { risk += 5; r += Tr.t(ctx, "Nome imita um app conhecido ({})").replace("{}", it) }
            if (ctx.packageManager.getLaunchIntentForPackage(p.packageName) == null) {
                risk += 4; r += Tr.t(ctx, "App sem ícone de abertura (oculto) instalado fora de loja confiável")
            }
        }
        return if (risk >= 4) Finding(p.packageName, label, risk, r) else null
    }

    fun analyzeFile(ctx: Context, f: File, bl: Set<String>, deep: Boolean = false): Verdict {
        var level = 0
        val r = mutableListOf<String>()
        val name = f.name.lowercase()
        val ext = f.extension.lowercase()
        val len = f.length()
        if (DOUBLE.matches(name)) { level = 2; r += Tr.t(ctx, "Extensão dupla enganosa (disfarçado de documento ou mídia)") }
        else if (ext in BAD_EXT) { level = 1; r += Tr.t(ctx, "Arquivo executável incomum em celular") }
        if (ext in MEDIA_EXT && len >= 4) try {
            val h = ByteArray(4)
            f.inputStream().use { it.read(h) }
            val elf = h[0] == 0x7f.toByte() && h[1] == 'E'.code.toByte() && h[2] == 'L'.code.toByte() && h[3] == 'F'.code.toByte()
            val mz = h[0] == 'M'.code.toByte() && h[1] == 'Z'.code.toByte()
            val dex = h[0] == 'd'.code.toByte() && h[1] == 'e'.code.toByte() && h[2] == 'x'.code.toByte()
            if (elf || mz || dex) { level = 2; r += Tr.t(ctx, "Executável disfarçado: o conteúdo não corresponde à extensão") }
        } catch (_: Exception) {}
        if (ext == "apk") {
            level = maxOf(level, 1)
            r += Tr.t(ctx, "APK fora da loja: instale apenas de fontes confiáveis")
            try {
                @Suppress("DEPRECATION")
                val pi = ctx.packageManager.getPackageArchiveInfo(f.path, 0)
                val ai = pi?.applicationInfo
                if (pi != null && ai != null) {
                    ai.sourceDir = f.path; ai.publicSourceDir = f.path
                    impersonates(ai.loadLabel(ctx.packageManager).toString(), pi.packageName)?.let {
                        level = 2; r += Tr.t(ctx, "Nome imita um app conhecido ({})").replace("{}", it)
                    }
                }
            } catch (_: Exception) {}
        }
        if (len in 1..200_000_000L && (!deep || ext in HASH_EXT)) try {
            if (sha256(f) in bl) { level = 2; r += Tr.t(ctx, "Assinatura (hash) conhecida de malware") }
        } catch (_: Exception) {}
        if (len in 1..2048L) try {
            if (f.readText(Charsets.ISO_8859_1).contains(EICAR)) { level = 2; r += Tr.t(ctx, "Arquivo de teste EICAR (inofensivo, usado para testar antivírus)") }
        } catch (_: Exception) {}
        return Verdict(level, r)
    }
}
