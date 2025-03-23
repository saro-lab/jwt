package me.saro.jwt.keyPair

import me.saro.jwt.JwtAlgorithm
import me.saro.jwt.JwtKey
import me.saro.jwt.JwtUtils
import me.saro.jwt.JwtUtils.Companion.bind
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

interface JwtKeyPairAlgorithm<T: JwtKey> : JwtAlgorithm {
    val keyAlgorithmName: String

    fun getKeyPairSignature(): Signature

    fun getKeyFactory(): KeyFactory = KeyFactory.getInstance(keyAlgorithmName)
    fun getKeyPairGenerator(): KeyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithmName)

    fun toKey(keyPair: KeyPair): T
    fun toKey(publicKey: PublicKey, privateKey: PrivateKey): T = toKey(KeyPair(publicKey, privateKey))
    fun toKey(publicKey: String, privateKey: String): T = toKey(toKeyPair(publicKey, privateKey))

    @Suppress("DEPRECATION")
    override fun parseKey(map: Map<String, String>): JwtKey =
        if (algorithmFullName == map["alg"]) {
            toKey(JwtUtils.normalizePem(map["pubKey"]!!), JwtUtils.normalizePem(map["priKey"]!!)).bind(map)
        } else {
            throw IllegalArgumentException("algorithm is not matched")
        }

    private fun toKeyPair(publicKey: String, privateKey: String): KeyPair =
        getKeyFactory().run {
            KeyPair(
                generatePublic(X509EncodedKeySpec(JwtUtils.decodeBase64(publicKey))),
                generatePrivate(PKCS8EncodedKeySpec(JwtUtils.decodeBase64(privateKey)))
            )
        }
}
