package me.saro.jwt.impl

import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.Keys
import me.saro.jwt.JwtKeyManager
import me.saro.jwt.KeyChain
import java.util.*
import java.util.concurrent.ConcurrentLinkedDeque
import kotlin.concurrent.timer

class DefaultJwtKeyManager private constructor(
    private val signatureAlgorithm: SignatureAlgorithm,
    private val keyRotationQueueSize: Int,
    keyRotationMinutes: Int
): JwtKeyManager() {

    companion object {
        @JvmStatic
        fun create(signatureAlgorithm: SignatureAlgorithm = SignatureAlgorithm.RS256): DefaultJwtKeyManager =
            DefaultJwtKeyManager(signatureAlgorithm, 3, 0)

        @JvmStatic
        fun create(signatureAlgorithm: SignatureAlgorithm, keyRotationQueueSize: Int): DefaultJwtKeyManager =
            DefaultJwtKeyManager(signatureAlgorithm, keyRotationQueueSize, 0)

        @JvmStatic
        fun create(signatureAlgorithm: SignatureAlgorithm, keyRotationQueueSize: Int, keyRotationMinutes: Int): DefaultJwtKeyManager =
            DefaultJwtKeyManager(signatureAlgorithm, keyRotationQueueSize, keyRotationMinutes)
    }

    private val queue: Deque<KeyChain> = ConcurrentLinkedDeque()
    private val timer: Timer?

    override fun getSignatureAlgorithm(): SignatureAlgorithm =
        signatureAlgorithm

    override fun getKeyChain(): KeyChain =
        queue.first

    @Throws(SecurityException::class)
    override fun findKeySet(kid: String?): KeyChain =
        queue.find { it.kid == kid }
            ?: throw SecurityException("Could not find key corresponding to kid")

    override fun rotate() {
        queue.addFirst(DefaultKeyChain(UUID.randomUUID().toString(), signatureAlgorithm, Keys.keyPairFor(signatureAlgorithm)))
        if (queue.size > keyRotationQueueSize) {
            queue.removeLast()
        }
    }

    init {

        if (keyRotationQueueSize < 3) {
            throw IllegalArgumentException("keyRotationQueueSize must be greater then 3")
        }

        if (keyRotationMinutes < 0) {
            throw IllegalArgumentException("keyRotationMinutes must be greater than or equal to 0 (0 is not use rotator thead task)")
        }

        rotate()
        timer = if (keyRotationMinutes > 0) {
            val period = 60_000L * keyRotationMinutes
            timer(null, true, period, period) {
                try {
                    rotate()
                } catch(e: Exception) { }
            }
        } else null
    }
}
