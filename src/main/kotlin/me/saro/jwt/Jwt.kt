package me.saro.jwt

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jsonMapper
import me.saro.jwt.JwtNode.Companion.parsePair
import me.saro.jwt.exception.JwtParseException
import me.saro.jwt.old.JwtNode
import java.time.Duration
import java.util.*

class Jwt {
    companion object {



        @JvmStatic
        fun parseOrNull(jwt: String): me.saro.jwt.old.JwtNode? = parsePair(jwt).first

        @JvmStatic
        fun parseOrThrow(jwt: String): JwtNode {
            val pair = parsePair(jwt)
            if (pair.first != null) {
                return pair.first!!
            } else {
                throw JwtParseException(pair.second?: "$jwt invalid jwt format")
            }
        }













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

        private var lastKid = System.currentTimeMillis()


        @JvmStatic
        fun normalizePem(key: String): String = key.replace(REGEX_PEM_NORMALIZE, "")

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

        @JvmStatic
        @Synchronized
        fun nextKid(kid: Long): String =
            System.currentTimeMillis()
                .coerceAtLeast(kid + 1)
                .coerceAtLeast(lastKid + 1)
                .also { lastKid = it }
                .toString()
    }
}
