package me.saro.jwt.core

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jsonMapper
import java.util.*

class JwtUtils {
    companion object {
        private val OBJECT_MAPPER: ObjectMapper = jsonMapper()
        private val DE_BASE64_URL: Base64.Decoder = Base64.getUrlDecoder()
        private val DE_BASE64: Base64.Decoder = Base64.getDecoder()
        private val TYPE_MAP = object: TypeReference<MutableMap<String, Any>>() {}
        private val TYPE_TEXT_MAP = object: TypeReference<MutableMap<String, String>>() {}
        private val EN_BASE64_URL_WOP: Base64.Encoder = Base64.getUrlEncoder().withoutPadding()
        private val REGEX_PEM_NORMALIZE = Regex("(\\s+|-----(BEGIN|END) .*?-----)")

        @JvmStatic
        fun writeValueAsBytes(obj: Any): ByteArray = OBJECT_MAPPER.writeValueAsBytes(obj)

        @JvmStatic
        fun readMap(src: ByteArray): MutableMap<String, Any> = OBJECT_MAPPER.readValue(src, TYPE_MAP)

        @JvmStatic
        fun readTextMap(src: ByteArray): MutableMap<String, String> = OBJECT_MAPPER.readValue(src, TYPE_TEXT_MAP)

        @JvmStatic
        fun decodeBase64(src: String): ByteArray = DE_BASE64.decode(src)

        @JvmStatic
        fun decodeBase64Url(src: ByteArray): ByteArray = DE_BASE64_URL.decode(src)

        @JvmStatic
        fun encodeToBase64UrlWop(src: ByteArray): ByteArray = EN_BASE64_URL_WOP.encode(src)

        @JvmStatic
        fun normalizePem(key: String) = key.replace(REGEX_PEM_NORMALIZE, "")
    }
}
