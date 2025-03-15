package me.saro.jwt

import me.saro.jwt.JwtUtils.Companion.exec
import java.util.concurrent.locks.ReentrantReadWriteLock

abstract class JwtKey: Comparable<JwtKey> {
    abstract val algorithm: JwtAlgorithm

    // signature
    abstract fun signature(body: ByteArray): ByteArray
    abstract fun verifySignature(body: ByteArray, signature: ByteArray): Boolean

    // jwt
    fun createJwt(): JwtNode.Builder = JwtNode.Builder(this)
    fun parseJwt(jwt: String): JwtNode = JwtNode.parse(jwt) { this }

    // lock
    private val lock = ReentrantReadWriteLock()
    private val writeLock = lock.writeLock()
    private val readLock = lock.readLock()

    // metadata
    private var _kid: String = JwtUtils.nextKid()
    var kid: String
        get() = readLock.exec { _kid }
        set(value) {
            if (value.isBlank()) {
                throw IllegalArgumentException("kid must not be blank")
            }
            if ((value.toLongOrNull() ?: 0) > 100000000000L) {
                throw IllegalArgumentException("custom kid must be less than 100000000000")
            }
            writeLock.exec { _kid = value }
        }
    private fun setKidWithSeq(kid: String) = writeLock.exec { JwtUtils.nextKid(kid); _kid = kid }
    private var _notBefore: Long = 0
    var notBefore: Long
        get() = readLock.exec { _notBefore }
        set(value) {
            if (value < 0) {
                throw IllegalArgumentException("notBefore must be greater than or equal to 0")
            }
            writeLock.exec { _notBefore = value }
        }
    private var _expire: Long = Long.MAX_VALUE
    var expire: Long
        get() = readLock.exec { _expire }
        set(value) {
            if (value < 0) {
                throw IllegalArgumentException("expire must be greater than or equal to 0")
            }
            writeLock.exec { _expire = value }
        }
    private var _issuedAt: Long = JwtUtils.epochSecond()
    var issuedAt: Long
        get() = readLock.exec { _issuedAt }
        set(value) {
            if (value < 0) {
                throw IllegalArgumentException("issuedAt must be greater than or equal to 0")
            }
            writeLock.exec { _issuedAt = value }
        }

    // convert
    abstract fun toMap(): Map<String, String>
    fun stringify(): String = JwtUtils.writeValueAsString(toMap())
    protected fun toMap(vararg pairs: Pair<String, String>): Map<String, String> = mapOf(
        "alg" to algorithm.algorithmFullName,
        "kid" to kid,
        "nbf" to notBefore.toString(),
        "iat" to issuedAt.toString(),
        "exp" to expire.toString(),
        *pairs
    )

    // method
    fun ready(now: Long = JwtUtils.epochSecond()): Boolean = notBefore <= now
    fun notReady(now: Long = JwtUtils.epochSecond()): Boolean = notBefore > now
    fun expired(now: Long = JwtUtils.epochSecond()): Boolean = expire < now
    fun notExpired(now: Long = JwtUtils.epochSecond()): Boolean = expire >= now

    // data
    fun clone(): JwtKey = algorithm.parseKey(stringify())
    override fun hashCode(): Int = kid.hashCode()
    override fun equals(other: Any?): Boolean = when (other) {
        is JwtKey -> other.kid == kid && other.algorithm == algorithm
        is JwtNode -> other.kid == kid && other.algorithm == algorithm.algorithmFullName
        is String -> other == kid
        else -> false
    }
    override fun compareTo(other: JwtKey): Int {
        val c = -expire.compareTo(other.expire)
        return if (c == 0) issuedAt.compareTo(other.issuedAt) else c
    }
    override fun toString(): String = stringify()
}
