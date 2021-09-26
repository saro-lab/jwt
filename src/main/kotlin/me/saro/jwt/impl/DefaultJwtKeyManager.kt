package me.saro.jwt.impl

import me.saro.jwt.JwtKeyManager
import me.saro.jwt.model.KeyChain
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.Keys
import java.util.*
import java.util.concurrent.ConcurrentLinkedDeque
import kotlin.concurrent.timer

class DefaultJwtKeyManager(
    private val signatureAlgorithm: SignatureAlgorithm = SignatureAlgorithm.RS256,
    private val keyRotationMinutes: Int = 0,
    private val keyRotationQueueSize: Int = 3
): JwtKeyManager() {
    private val queue: Deque<KeyChain> = ConcurrentLinkedDeque()
    private val timer: Timer?

    override fun getSignatureAlgorithm(): SignatureAlgorithm =
        signatureAlgorithm

    override fun getKeyChain(): KeyChain =
        queue.first

    @Throws(SecurityException::class)
    override fun findKeySet(kid: Long): KeyChain =
        queue.find { it.kid == kid }
            ?: throw SecurityException("key not found")

    override fun rotate() {
        queue.addFirst(KeyChain(System.currentTimeMillis(), Keys.keyPairFor(SignatureAlgorithm.RS256)))
        if (queue.size > keyRotationQueueSize) {
            queue.removeLast()
        }
    }

    init {
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
