package me.saro.jwt.store

import me.saro.jwt.Jwt
import me.saro.jwt.JwtKey
import me.saro.jwt.JwtUtils
import me.saro.jwt.JwtUtils.Companion.exec
import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import java.util.concurrent.locks.ReentrantReadWriteLock

class JwtKeyStoreMirror private constructor(
    private var list: Collection<JwtKey> = listOf()
): JwtKeyStore {
    private val lock: ReentrantReadWriteLock = ReentrantReadWriteLock()
    private val writeLock: ReentrantReadWriteLock.WriteLock = lock.writeLock()
    private val readLock: ReentrantReadWriteLock.ReadLock = lock.readLock()

    fun imports(jsonArray: String?): JwtKeyStore {
        if (!jsonArray.isNullOrBlank()) {
            val now = JwtUtils.epochSecond()
            val items = Jwt.parseKeyArray(jsonArray)
                .filter { it.notExpired(now) }
                .sorted()
            writeLock.exec { list = items }
        }
        return this
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

    override fun findKey(kid: String): JwtKey = readLock.exec {
        list.firstOrNull { it.kid == kid }
    } ?: throw JwtException(JwtExceptionCode.NOT_FOUND_KEY, "not found kid: $kid")

    override fun getAllKeysForMonitor(): List<JwtKey> =
        readLock.exec { list.stream().map { it.clone() }.toList() }

    override fun exports(): String =
        readLock.exec(JwtUtils.epochSecond()) { now ->
            list.filter { it.notExpired(now) }.joinToString(",", "[", "]") { it.toString() }
        }

    class Builder {
        private val store: JwtKeyStoreMirror = JwtKeyStoreMirror()

        fun imports(jsonArray: String?): Builder {
            store.imports(jsonArray)
            return this
        }

        fun build(): JwtKeyStoreMirror {
            return store
        }
    }
}