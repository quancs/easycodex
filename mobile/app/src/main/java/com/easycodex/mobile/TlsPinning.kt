package com.easycodex.mobile

import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import okhttp3.OkHttpClient

/**
 * 自签证书 pinning：用于 wss/https 连接（relay 自签证书穿透公共 frp 的 HTTP 拦截）。
 * 证书 SHA-256 指纹经二维码 tlsfp 参数带外分发；指纹匹配即信任，否则回落系统 CA。
 */
object TlsPinning {

    /** 当前活动主机的 tlsfp（由 EasyCodexController 同步；媒体下载等非注入场景使用） */
    @Volatile
    var activeFingerprint: String? = null

    private fun sha256Hex(data: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }

    private fun certMatchesFingerprint(cert: X509Certificate?, fingerprint: String): Boolean {
        if (cert == null || fingerprint.isBlank()) return false
        return runCatching { sha256Hex(cert.encoded).equals(fingerprint, ignoreCase = true) }.getOrDefault(false)
    }

    private fun defaultTrustManager(): X509TrustManager {
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(null as KeyStore?)
        return tmf.trustManagers.filterIsInstance<X509TrustManager>().first()
    }

    private class PinningTrustManager(
        private val fingerprint: String,
        private val fallback: X509TrustManager,
    ) : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>, authType: String) =
            fallback.checkClientTrusted(chain, authType)

        override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String) {
            // 叶证书指纹命中（自签 pinning）→ 直接信任；否则走系统 CA（公共证书场景）
            if (certMatchesFingerprint(chain.firstOrNull(), fingerprint)) return
            fallback.checkServerTrusted(chain, authType)
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> = fallback.acceptedIssuers
    }

    private fun sslSocketFactory(fingerprint: String): Pair<SSLSocketFactory, X509TrustManager> {
        val tm = PinningTrustManager(fingerprint, defaultTrustManager())
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, arrayOf<TrustManager>(tm), null)
        return ctx.socketFactory to tm
    }

    /** 指纹命中时放行任意主机名（自签证书 CN 与隧道域名不一致）；否则默认主机名校验 */
    private fun hostnameVerifier(fingerprint: String): HostnameVerifier {
        val fallback = HttpsURLConnection.getDefaultHostnameVerifier()
        return HostnameVerifier { host, session ->
            val pinned = runCatching {
                certMatchesFingerprint(session.peerCertificates.firstOrNull() as? X509Certificate, fingerprint)
            }.getOrDefault(false)
            pinned || fallback.verify(host, session)
        }
    }

    /** 应用到 OkHttpClient.Builder（tlsfp 为空则原样返回） */
    fun applyTo(builder: OkHttpClient.Builder, fingerprint: String?): OkHttpClient.Builder {
        if (fingerprint.isNullOrBlank()) return builder
        val (factory, tm) = sslSocketFactory(fingerprint)
        return builder.sslSocketFactory(factory, tm).hostnameVerifier(hostnameVerifier(fingerprint))
    }

    /** 应用到 HttpsURLConnection（媒体下载等；tlsfp 为空则不动） */
    fun applyTo(connection: java.net.URLConnection, fingerprint: String?) {
        if (fingerprint.isNullOrBlank() || connection !is HttpsURLConnection) return
        val (factory, _) = sslSocketFactory(fingerprint)
        connection.sslSocketFactory = factory
        connection.hostnameVerifier = hostnameVerifier(fingerprint)
    }
}
