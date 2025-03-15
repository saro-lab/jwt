package me.saro.jwt.store

import me.saro.jwt.Jwt
import me.saro.jwt.JwtAlgorithm
import me.saro.jwt.JwtKey
import me.saro.jwt.JwtUtils
import me.saro.jwt.JwtUtils.Companion.bind
import me.saro.jwt.JwtUtils.Companion.exec
import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import java.time.Duration
import java.util.concurrent.locks.ReentrantReadWriteLock

class JwtKeyStoreProvider private constructor(): JwtKeyStore {
    private val lock = ReentrantReadWriteLock()
    private val writeLock = lock.writeLock()
    private val readLock = lock.readLock()

    private var algorithm: JwtAlgorithm = Jwt.HS256
    private var genKey: (JwtAlgorithm) -> JwtKey = { it.newRandomKey() }
    private var list: List<JwtKey> = listOf()

    private var keySyncTime: Long = 0
    private var keyExpireTime: Long = 0

    fun issue() {
        val now = JwtUtils.epochSecond()
        val map = mutableMapOf<String, String>()
        if (keySyncTime != 0L) { map["nbf"] = (now + keySyncTime).toString() }
        if (keyExpireTime != 0L) { map["exp"] = (now + keyExpireTime).toString() }

        @Suppress("DuplicatedCode")
        val key = genKey(algorithm).bind(map)
        putKeys(listOf(key))
    }

    private fun putKeys(keys: List<JwtKey>) {
        val alg = algorithm.algorithmFullName
        if (keys.any { it.algorithm.algorithmFullName != alg }) {
            throw JwtException(JwtExceptionCode.KEY_STORE_EXCEPTION, "algorithm is not matched")
        }
        writeLock.exec(JwtUtils.epochSecond()) { now ->
            list = (keys + list).filter { it.notExpired(now) }.sorted()
        }
    }

    fun removeExpiredKeys() =
        writeLock.exec(JwtUtils.epochSecond()) { now ->
            list = list.filter { it.notExpired(now) }
        }

    override fun getCurrentKey(): JwtKey {
        var key: JwtKey? = null
        readLock.exec(JwtUtils.epochSecond()) { now ->
            for (k in list) {
                if (k.notReady(now)) { continue } else if (k.notExpired(now)) { key = k }
                break
            }
        }
        return key?: throw JwtException(JwtExceptionCode.NOT_FOUND_KEY, "not found key")
    }

    override fun findKey(kid: String): JwtKey =
        readLock.exec { list.find { it.kid == kid } }
            ?: throw JwtException(JwtExceptionCode.NOT_FOUND_KEY, "not found kid: $kid")

    override fun exports(): String =
        readLock.exec(JwtUtils.epochSecond()) { now ->
            list.filter { it.notExpired(now) }
                .joinToString(",", "[", "]") { it.toString() }
        }

    override fun getAllKeysForMonitor(): List<JwtKey> =
        readLock.exec { list.stream().map { it.clone() }.toList() }

    class Builder {
        private val provider: JwtKeyStoreProvider = JwtKeyStoreProvider()

        fun <T: JwtAlgorithm> algorithm(algorithm: T, genKey: (T) -> JwtKey): Builder = apply {
            provider.algorithm = algorithm
            @Suppress("UNCHECKED_CAST")
            provider.genKey = genKey as (JwtAlgorithm) -> JwtKey
        }

        fun <T: JwtAlgorithm> algorithm(algorithm: T): Builder = apply {
            provider.algorithm = algorithm
            provider.genKey = { algorithm.newRandomKey() }
        }

        fun keySyncTime(keySyncTime: Duration): Builder = apply {
            val seconds = keySyncTime.seconds
            if (seconds < 0) {
                throw IllegalArgumentException("keySyncTime must be greater than or equal to 0")
            }
            provider.keySyncTime = seconds
        }

        fun keyExpireTime(keyExpireTime: Duration): Builder = apply {
            val seconds = keyExpireTime.seconds
            if (seconds < 0) {
                throw IllegalArgumentException("keyExpireTime must be greater than or equal to 0")
            }
            provider.keyExpireTime = seconds
        }

        fun build(): JwtKeyStoreProvider = build(null)

        fun build(jsonArray: String?): JwtKeyStoreProvider {
            if (!jsonArray.isNullOrBlank()) {
                provider.putKeys(Jwt.parseKeyArray(jsonArray))
            }
            return provider
        }
    }
}
