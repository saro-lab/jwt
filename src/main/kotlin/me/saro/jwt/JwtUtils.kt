package me.saro.jwt

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jsonMapper
import java.time.Duration
import java.util.*
import java.util.concurrent.locks.ReentrantReadWriteLock
import me.saro.jwt.JwtAlgorithm.*
import me.saro.jwt.exception.JwtIllegalArgumentException
import java.security.Key
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class JwtUtils {
    companion object {






        private val OBJECT_MAPPER: ObjectMapper = jsonMapper()
        private val DE_BASE64_URL: Base64.Decoder = Base64.getUrlDecoder()
        private val EN_BASE64_URL: Base64.Encoder = Base64.getUrlEncoder()
        private val DE_BASE64: Base64.Decoder = Base64.getDecoder()
        private val TYPE_MAP = object: TypeReference<MutableMap<String, Any>>() {}
        private val TYPE_TEXT_MAP = object: TypeReference<MutableMap<String, String>>() {}
        private val TYPE_TEXT_MAP_LIST = object: TypeReference<List<MutableMap<String, String>>>() {}
        private val EN_BASE64 = Base64.getEncoder()
        private val EN_BASE64_URL_WOP: Base64.Encoder = Base64.getUrlEncoder().withoutPadding()
        private val REGEX_PEM_NORMALIZE = Regex("(\\s+|-----(BEGIN|END) .*?-----)")
        private val JWT_KEY_SET_KID_WITH_SEQ = JwtKey::class.java.getDeclaredMethod("setKidWithSeq", String::class.java)
            .also {  it.isAccessible = true }

        private var lastKid = System.currentTimeMillis()


        @JvmStatic
        fun normalizePem(key: String) = key.replace(REGEX_PEM_NORMALIZE, "")

        @JvmStatic
        fun writeValueAsString(obj: Any): String = OBJECT_MAPPER.writeValueAsString(obj)

        @JvmStatic
        fun writeValueAsBytes(obj: Any): ByteArray = OBJECT_MAPPER.writeValueAsBytes(obj)

        @JvmStatic
        fun readMap(src: ByteArray): MutableMap<String, Any> = OBJECT_MAPPER.readValue(src, TYPE_MAP)

        @JvmStatic
        fun readTextMap(src: String): MutableMap<String, String> = OBJECT_MAPPER.readValue(src, TYPE_TEXT_MAP)

        @JvmStatic
        fun readTextMap(src: ByteArray): MutableMap<String, String> = OBJECT_MAPPER.readValue(src, TYPE_TEXT_MAP)

        @JvmStatic
        fun readTextMapList(src: String): List<MutableMap<String, String>> = OBJECT_MAPPER.readValue(src, TYPE_TEXT_MAP_LIST)

        @JvmStatic
        fun <T> readValue(src: String, valueTypeRef: TypeReference<T>): T = OBJECT_MAPPER.readValue(src, valueTypeRef)

        @JvmStatic
        fun decodeBase64(src: String): ByteArray = DE_BASE64.decode(src)

        @JvmStatic
        fun decodeBase64Url(src: ByteArray): ByteArray = DE_BASE64_URL.decode(src)

        @JvmStatic
        fun encodeBase64String(src: ByteArray): String = EN_BASE64.encodeToString(src)

        @JvmStatic
        fun encodeBase64String(src: String): String = EN_BASE64.encodeToString(src.toByteArray())

        @JvmStatic
        fun encodeBase64UrlString(src: ByteArray): String = EN_BASE64_URL.encodeToString(src)

        @JvmStatic
        fun encodeBase64UrlString(src: String): String = EN_BASE64_URL.encodeToString(src.toByteArray())

        @JvmStatic
        fun encodeToBase64UrlWop(src: ByteArray): ByteArray = EN_BASE64_URL_WOP.encode(src)

        @JvmStatic
        fun encodeToBase64String(src: ByteArray): String = EN_BASE64.encodeToString(src)

        @JvmStatic
        fun encodeHex(bytes: ByteArray): String =
            HexFormat.of().formatHex(bytes)

        @JvmStatic
        fun decodeHex(hex: String): ByteArray =
            HexFormat.of().parseHex(hex)

        @JvmStatic
        // epoch second, Instant.now().epochSecond is slower than System.currentTimeMillis() / 1000
        fun epochSecond(): Long = System.currentTimeMillis() / 1000

        @JvmStatic
        fun epochSecond(duration: Duration): Long = (System.currentTimeMillis() / 1000) + duration.seconds

        fun <R> ReentrantReadWriteLock.WriteLock.exec(exec: () -> R): R = try { lock(); exec() } finally { unlock() }
        fun <R> ReentrantReadWriteLock.ReadLock.exec(exec: () -> R): R = try { lock(); exec() } finally { unlock() }
        fun <T, R> ReentrantReadWriteLock.WriteLock.exec(t: T, exec: (T) -> R): R = try { lock(); exec(t) } finally { unlock() }
        fun <T, R> ReentrantReadWriteLock.ReadLock.exec(t: T, exec: (T) -> R): R = try { lock(); exec(t) } finally { unlock() }

        @JvmStatic
        fun nextKid(): String = nextKid(0L)

        @JvmStatic
        fun nextKid(kid: String?): String = nextKid(kid?.toLongOrNull() ?: 0L)

        @JvmStatic
        @Synchronized
        fun nextKid(kid: Long): String =
            System.currentTimeMillis()
                .coerceAtLeast(kid + 1)
                .coerceAtLeast(lastKid + 1)
                .also { lastKid = it }
                .toString()

        @Deprecated("do not use this method")
        fun JwtKey.bind(map: Map<String, String>) = apply {
            map["kid"]?.also { nextKid(it); JWT_KEY_SET_KID_WITH_SEQ.invoke(this, it) }
            map["nbf"]?.toLongOrNull()?.also { notBefore = it }
            map["exp"]?.toLongOrNull()?.also { expire = it }
            map["iat"]?.toLongOrNull()?.also { issuedAt = it }
        }
    }
}
