package me.saro.jwt.keyPair

import me.saro.jwt.JwtAlgorithm
import me.saro.jwt.JwtKey
import me.saro.jwt.JwtUtils
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.util.*

class JwtRsKey(
    algorithmFullNameCopy: String,
    override val keyPair: KeyPair
): JwtRsAlgorithm(algorithmFullNameCopy), JwtKeyPair {
    override var kid: String = UUID.randomUUID().toString()
    override var notBefore: Long = 0
    override var expire: Long = 0
    override val algorithm: JwtAlgorithm = this

    override fun toString(): String = stringify
    override fun hashCode(): Int = stringify.hashCode()
    override fun equals(other: Any?): Boolean = other is JwtKey && stringify == other.stringify

    override val public: PublicKey get() = keyPair.public
    override val private: PrivateKey get() = keyPair.private
    override fun getKeyPairSignature(): Signature = super<JwtRsAlgorithm>.getKeyPairSignature()
}
