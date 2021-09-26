package me.saro.jwt

import io.jsonwebtoken.*
import me.saro.jwt.io.JwtBuilder
import me.saro.jwt.io.JwtReader
import me.saro.jwt.model.KeyChain
import java.security.Key

abstract class JwtKeyManager{

    abstract fun getSignatureAlgorithm(): SignatureAlgorithm

    abstract fun getKeyChain(): KeyChain

    abstract fun rotate(): Unit

    @Throws(SecurityException::class)
    abstract fun findKeySet(kid: Long): KeyChain

    fun getJwtBuilder(): JwtBuilder =
        JwtBuilder(getSignatureAlgorithm(), getKeyChain())

    @Throws(io.jsonwebtoken.security.SecurityException::class)
    fun parse(jwt: String): JwtReader {
        val jwt = Jwts
            .parserBuilder()
            .setSigningKeyResolver(signingKeyResolverAdapter)
            .build()
            .parseClaimsJws(jwt)
        return JwtReader(jwt, findKeySet(jwt.header["kid"] as Long))
    }

    private val signingKeyResolverAdapter = object : SigningKeyResolverAdapter() {
        @Throws(io.jsonwebtoken.security.SecurityException::class)
        override fun resolveSigningKey(header: JwsHeader<*>, claims: Claims): Key {
            if (header["alg"] as String != getSignatureAlgorithm().name) {
                throw io.jsonwebtoken.security.SecurityException("algorithm is not ${getSignatureAlgorithm().name}")
            }
            val kid = (header["kid"] as Long)
            return findKeySet(kid).keyPair.private
        }
    }
}
