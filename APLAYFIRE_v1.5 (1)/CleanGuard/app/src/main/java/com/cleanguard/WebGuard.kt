package com.cleanguard

import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors

object WebGuard {
    private val BAD_TLD = setOf("tk", "ml", "ga", "cf", "gq", "zip", "mov", "click", "monster")
    private val BRANDS = mapOf("whatsapp" to listOf("whatsapp.com", "whatsapp.net", "wa.me"),
        "instagram" to listOf("instagram.com", "cdninstagram.com"), "facebook" to listOf("facebook.com", "fbcdn.net", "fb.com"),
        "nubank" to listOf("nubank.com.br", "nu.com.br"), "itau" to listOf("itau.com.br", "itau.com"),
        "bradesco" to listOf("bradesco.com.br"), "paypal" to listOf("paypal.com", "paypalobjects.com"),
        "netflix" to listOf("netflix.com", "nflxvideo.net"), "freefire" to listOf("garena.com", "freefiremobile.com"),
        "mercadolivre" to listOf("mercadolivre.com.br", "mercadolibre.com", "mlstatic.com"))
    @Volatile var doms: Set<String> = emptySet()

    fun load(c: Context) {
        val s = HashSet<String>()
        fun add(l: String) { val t = l.trim().lowercase(); if (t.isNotEmpty() && !t.startsWith("#")) s += t }
        try { c.assets.open("domains.txt").bufferedReader().forEachLine { add(it) } } catch (_: Exception) {}
        try { val f = File(c.filesDir, "domains.txt"); if (f.exists()) f.forEachLine { add(it) } } catch (_: Exception) {}
        doms = s
    }

    fun verdict(c: Context, host: String): Verdict {
        var level = 0; var s = 0
        val r = mutableListOf<String>()
        val labels = host.split('.')
        for (i in labels.indices) if (labels.drop(i).joinToString(".") in doms) { level = 2; r += Tr.t(c, "Domínio na lista de ameaças"); break }
        if (host.contains("xn--")) { s += 2; r += Tr.t(c, "Endereço com caracteres disfarçados (punycode)") }
        if (labels.last() in BAD_TLD) { s += 1; r += Tr.t(c, "Extensão de domínio muito usada em golpes") }
        for ((b, ok) in BRANDS) if (host.contains(b) && ok.none { host == it || host.endsWith(".$it") }) {
            s += 2; r += Tr.t(c, "Imita a marca {}").replace("{}", b)
        }
        if (host.count { it == '-' } >= 4) { s += 1; r += Tr.t(c, "Endereço com muitos hifens") }
        if (level < 2 && s >= 3) level = 1
        return Verdict(level, if (level == 0) emptyList() else r)
    }
}

// Proteção web: VPN local que só captura consultas DNS. Nada do seu tráfego passa por servidores nossos.
class WebGuardService : VpnService() {
    companion object {
        private val allowed = ConcurrentHashMap<String, Long>()
        private val seen = ConcurrentHashMap<String, Long>()
        @Volatile var running = false
        fun allow(host: String) { allowed[host] = System.currentTimeMillis() + 15 * 60_000 }
        private fun isAllowed(host: String) = allowed.entries.any { it.value > System.currentTimeMillis() && (host == it.key || host.endsWith("." + it.key)) }
        fun start(c: Context) {
            val i = Intent(c, WebGuardService::class.java)
            if (Build.VERSION.SDK_INT >= 26) c.startForegroundService(i) else c.startService(i)
        }
    }
    private var tun: ParcelFileDescriptor? = null
    private val pool = Executors.newCachedThreadPool()

    override fun onStartCommand(i: Intent?, f: Int, id: Int): Int {
        Notifier.channels(this)
        val n = Notifier.ongoing(this)
        if (Build.VERSION.SDK_INT >= 34) startForeground(2, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE) else startForeground(2, n)
        if (tun == null) {
            WebGuard.load(this)
            tun = Builder().setSession("APLAYFIRE").addAddress("10.9.9.1", 32).addDnsServer("10.9.9.2")
                .addRoute("10.9.9.2", 32).setBlocking(true).establish()
            val fd = tun
            if (fd == null) { stopSelf(); return START_NOT_STICKY }
            running = true
            Thread { loop(fd) }.start()
        }
        return START_STICKY
    }

    private fun loop(fd: ParcelFileDescriptor) {
        val inp = FileInputStream(fd.fileDescriptor)
        val out = FileOutputStream(fd.fileDescriptor)
        val buf = ByteArray(32767)
        try {
            while (running) {
                val n = inp.read(buf)
                if (n <= 0) continue
                val pkt = buf.copyOf(n)
                pool.execute { try { handle(pkt, out) } catch (_: Exception) {} }
            }
        } catch (_: Exception) {}
    }

    private fun qname(d: ByteArray): Pair<String, Int>? {
        var i = 12
        val sb = StringBuilder()
        while (i < d.size) {
            val l = d[i].toInt() and 255
            if (l == 0) return if (sb.isEmpty()) null else Pair(sb.toString().lowercase(), i + 5)
            if (l > 63 || i + l >= d.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            sb.append(String(d, i + 1, l, Charsets.ISO_8859_1))
            i += l + 1
        }
        return null
    }

    private fun forward(q: ByteArray, up: String): ByteArray? {
        val s = DatagramSocket()
        return try {
            protect(s); s.soTimeout = 4000
            s.send(DatagramPacket(q, q.size, InetAddress.getByName(up), 53))
            val b = ByteArray(4096); val dp = DatagramPacket(b, b.size)
            s.receive(dp); b.copyOf(dp.length)
        } catch (_: Exception) { null } finally { s.close() }
    }

    private fun alert(host: String, v: Verdict) {
        val now = System.currentTimeMillis()
        if (now - (seen[host] ?: 0L) < 20_000) return
        seen[host] = now
        ThreatLog.add(this, "web", host, host, v.level, v.reasons)
        if (!Overlay.show(this, "web", host, host, v.level, v.reasons))
            Notifier.threat(this, host.hashCode(), Tr.t(this, "Download suspeito: ") + host, v.reasons.joinToString("\n• ", "• "), null)
    }

    private fun handle(p: ByteArray, out: FileOutputStream) {
        if (p.size < 28 || (p[0].toInt() shr 4) != 4) return
        val ihl = (p[0].toInt() and 15) * 4
        if (p[9].toInt() != 17 || (((p[ihl + 2].toInt() and 255) shl 8) or (p[ihl + 3].toInt() and 255)) != 53) return
        val dns = p.copyOfRange(ihl + 8, p.size)
        val (host, qend) = qname(dns) ?: return
        val ok = isAllowed(host)
        fun nx(): ByteArray { val r = dns.copyOf(qend); r[2] = 0x81.toByte(); r[3] = 0x83.toByte(); for (k in 6..11) r[k] = 0; return r }
        val resp: ByteArray
        if (!ok && WebGuard.verdict(this, host).also { if (it.level > 0) alert(host, it) }.level > 0) resp = nx()
        else {
            val up = forward(dns, if (ok) "1.1.1.1" else "1.1.1.2") ?: return
            val cf = !ok && up.size > 16 && (up[3].toInt() and 15) == 0 && up[7].toInt() > 0 && up.takeLast(4).all { it.toInt() == 0 }
            if (cf) { alert(host, Verdict(2, listOf(Tr.t(this, "Bloqueado pelo filtro de ameaças (Cloudflare)")))); resp = nx() } else resp = up
        }
        val total = ihl + 8 + resp.size
        val r = ByteArray(total)
        System.arraycopy(p, 0, r, 0, ihl)
        System.arraycopy(p, 16, r, 12, 4); System.arraycopy(p, 12, r, 16, 4)
        r[2] = (total shr 8).toByte(); r[3] = total.toByte(); r[10] = 0; r[11] = 0
        var sum = 0
        for (k in 0 until ihl step 2) sum += ((r[k].toInt() and 255) shl 8) or (r[k + 1].toInt() and 255)
        while (sum shr 16 != 0) sum = (sum and 0xffff) + (sum shr 16)
        val ck = sum.inv() and 0xffff
        r[10] = (ck shr 8).toByte(); r[11] = ck.toByte()
        r[ihl] = p[ihl + 2]; r[ihl + 1] = p[ihl + 3]; r[ihl + 2] = p[ihl]; r[ihl + 3] = p[ihl + 1]
        val ul = 8 + resp.size
        r[ihl + 4] = (ul shr 8).toByte(); r[ihl + 5] = ul.toByte(); r[ihl + 6] = 0; r[ihl + 7] = 0
        System.arraycopy(resp, 0, r, ihl + 8, resp.size)
        synchronized(out) { out.write(r) }
    }

    override fun onDestroy() {
        running = false
        try { tun?.close() } catch (_: Exception) {}
        tun = null; pool.shutdownNow()
        super.onDestroy()
    }
}
