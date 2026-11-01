package com.easycodex.mobile

import android.util.Base64
import java.security.SecureRandom
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.json.JSONObject

/**
 * E2ECrypto — EasyCodex E2E v1 端到端加密（Android 侧）
 *
 * 与 agent-relay/src/e2e-crypto.ts 协议常量严格一致：
 * - 握手：客户端 X25519 公钥 + HMAC(apiKey,'e2e-c1:'+clientPub) 证明；apiKey 永不上线
 * - 会话密钥：HKDF-SHA256(shared, salt=clientPubRaw||serverPubRaw, info='easycodex-e2e-v1')
 * - 帧：{"enc": base64(nonce12 || AES-256-GCM(ct) || tag16)}
 * - 媒体：签名 HMAC(apiKey,'media:'+ts+':'+originalUrl)，密钥 HKDF(apiKey,'easycodex-media-salt','easycodex-media-v1')
 *
 * 使用 BouncyCastle 轻量 API（不注册 JCA Provider，鸿蒙/无 GMS 设备安全）。
 */
object E2ECrypto {
    private const val E2E_INFO = "easycodex-e2e-v1"
    private const val CLIENT_PROOF_PREFIX = "e2e-c1:"
    private const val SERVER_PROOF_PREFIX = "e2e-s1:"
    private const val MEDIA_KEY_SALT = "easycodex-media-salt"
    private const val MEDIA_KEY_INFO = "easycodex-media-v1"
    private const val MEDIA_SIGN_PREFIX = "media:"
    private const val GCM_TAG_BITS = 128
    private const val NONCE_LEN = 12

    private val random = SecureRandom()

    private fun b64(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)
    private fun unb64(text: String): ByteArray = Base64.decode(text, Base64.NO_WRAP)

    private fun hmacSha256(key: String, message: String): ByteArray {
        val mac = HMac(SHA256Digest())
        mac.init(KeyParameter(key.toByteArray(Charsets.UTF_8)))
        val data = message.toByteArray(Charsets.UTF_8)
        mac.update(data, 0, data.size)
        val out = ByteArray(mac.macSize)
        mac.doFinal(out, 0)
        return out
    }

    private fun hkdf(ikm: ByteArray, salt: ByteArray, info: String): ByteArray {
        val gen = HKDFBytesGenerator(SHA256Digest())
        gen.init(HKDFParameters(ikm, salt, info.toByteArray(Charsets.UTF_8)))
        val out = ByteArray(32)
        gen.generateBytes(out, 0, out.size)
        return out
    }

    private fun constantTimeEqualsB64(a: String, b: String): Boolean {
        val ab = runCatching { unb64(a) }.getOrNull() ?: return false
        val bb = runCatching { unb64(b) }.getOrNull() ?: return false
        if (ab.size != bb.size || ab.isEmpty()) return false
        var diff = 0
        for (i in ab.indices) diff = diff or (ab[i].toInt() xor bb[i].toInt())
        return diff == 0
    }

    private fun gcmCrypt(encrypt: Boolean, key: ByteArray, nonce: ByteArray, input: ByteArray): ByteArray {
        val cipher = GCMBlockCipher.newInstance(AESEngine.newInstance())
        cipher.init(encrypt, AEADParameters(KeyParameter(key), GCM_TAG_BITS, nonce))
        val out = ByteArray(cipher.getOutputSize(input.size))
        var len = cipher.processBytes(input, 0, input.size, out, 0)
        len += cipher.doFinal(out, len)
        return out.copyOf(len)
    }

    /** 客户端握手：生成 X25519 临时密钥对与 apiKey 证明（apiKey 不上线） */
    class Handshake(private val apiKey: String) {
        private val privateKey: X25519PrivateKeyParameters
        private val publicKeyRaw: ByteArray
        val clientPubB64: String
        val proofB64: String

        init {
            val gen = X25519KeyPairGenerator()
            gen.init(X25519KeyGenerationParameters(random))
            val pair = gen.generateKeyPair()
            privateKey = pair.private as X25519PrivateKeyParameters
            publicKeyRaw = (pair.public as X25519PublicKeyParameters).encoded
            clientPubB64 = b64(publicKeyRaw)
            proofB64 = b64(hmacSha256(apiKey, CLIENT_PROOF_PREFIX + clientPubB64))
        }

        /** 校验服务端证明并派生会话密钥；失败返回 null */
        fun complete(serverPubB64: String, serverHmacB64: String): Session? {
            val expected = b64(hmacSha256(apiKey, "$SERVER_PROOF_PREFIX$serverPubB64:$clientPubB64"))
            if (!constantTimeEqualsB64(expected, serverHmacB64)) return null
            return runCatching {
                val serverPubRaw = unb64(serverPubB64)
                val agreement = X25519Agreement()
                agreement.init(privateKey)
                val shared = ByteArray(agreement.agreementSize)
                agreement.calculateAgreement(X25519PublicKeyParameters(serverPubRaw, 0), shared, 0)
                Session(hkdf(shared, publicKeyRaw + serverPubRaw, E2E_INFO))
            }.getOrNull()
        }
    }

    /** 已建立的加密会话：出入站帧加解密 */
    class Session(private val sessionKey: ByteArray) {
        fun encryptEnvelope(plaintextJson: String): String {
            val nonce = ByteArray(NONCE_LEN).also { random.nextBytes(it) }
            val ct = gcmCrypt(true, sessionKey, nonce, plaintextJson.toByteArray(Charsets.UTF_8))
            return JSONObject().put("enc", b64(nonce + ct)).toString()
        }

        fun decryptEnvelope(envelopeJson: String): String {
            val frame = unb64(JSONObject(envelopeJson).getString("enc"))
            val nonce = frame.copyOfRange(0, NONCE_LEN)
            val ct = frame.copyOfRange(NONCE_LEN, frame.size)
            return String(gcmCrypt(false, sessionKey, nonce, ct), Charsets.UTF_8)
        }
    }

    // ---------- /media/* HTTP ----------

    fun mediaKey(apiKey: String): ByteArray =
        hkdf(apiKey.toByteArray(Charsets.UTF_8), MEDIA_KEY_SALT.toByteArray(Charsets.UTF_8), MEDIA_KEY_INFO)

    fun mediaTimestamp(): String = System.currentTimeMillis().toString()

    /** 签名：base64(HMAC(apiKey, 'media:'+ts+':'+originalUrl))；originalUrl 为请求 path+query（含 enc=1） */
    fun mediaSignature(apiKey: String, timestamp: String, originalUrl: String): String =
        b64(hmacSha256(apiKey, "$MEDIA_SIGN_PREFIX$timestamp:$originalUrl"))

    /** 解密媒体响应体（nonce || ct || tag） */
    fun decryptMedia(key: ByteArray, data: ByteArray): ByteArray {
        if (data.size < NONCE_LEN + 16 + 1) throw IllegalArgumentException("Encrypted payload too short")
        val nonce = data.copyOfRange(0, NONCE_LEN)
        val ct = data.copyOfRange(NONCE_LEN, data.size)
        return gcmCrypt(false, key, nonce, ct)
    }
}
