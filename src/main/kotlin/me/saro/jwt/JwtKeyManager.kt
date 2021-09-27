package me.saro.jwt

import io.jsonwebtoken.*
import me.saro.jwt.io.JwtBuilder
import me.saro.jwt.io.JwtReader
import me.saro.jwt.model.KeyChain
import java.security.Key

abstract class JwtKeyManager{

    abstract fun getSignatureAlgorithm(): SignatureAlgorithm

    abstract fun getKeyChain(): KeyChain

    abstract fun rotate()

    @Throws(SecurityException::class)
    abstract fun findKeySet(kid: String?): KeyChain

    fun getJwtBuilder(): JwtBuilder =
        JwtBuilder(getSignatureAlgorithm(), getKeyChain())

    @Throws(io.jsonwebtoken.security.SecurityException::class)
    fun parse(jwt: String): JwtReader {
        val jwtClaims = Jwts
            .parserBuilder()
            .setSigningKeyResolver(signingKeyResolverAdapter)
            .build()
            .parseClaimsJws(jwt)
        return JwtReader(jwtClaims, findKeySet(jwtClaims.header["kid"] as String?))
    }

    private val signingKeyResolverAdapter = object : SigningKeyResolverAdapter() {
        @Throws(io.jsonwebtoken.security.SecurityException::class)
        override fun resolveSigningKey(header: JwsHeader<*>, claims: Claims): Key {
            val keyChain = (header["kid"] as String?)
                ?.let { findKeySet(it) }
                ?: throw SecurityException("does not found kid in jwt")

            if (header["alg"] as String? != keyChain.algorithm.name) {
                throw SecurityException("does not match algorithm: jwt.algorithm != keyChain.algorithm")
            }

            return keyChain.keyPair.private
        }
    }
}
