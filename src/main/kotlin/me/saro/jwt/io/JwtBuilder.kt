package me.saro.jwt.io

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import me.saro.jwt.model.KeyChain
import java.util.*

class JwtBuilder constructor(
    private val signatureAlgorithm: SignatureAlgorithm,
    private val keyChain: KeyChain,
    private val header: MutableMap<String, Any>,
    private val claims: MutableMap<String, Any>
) {
    constructor(signatureAlgorithm: SignatureAlgorithm, keyChain: KeyChain): this(signatureAlgorithm, keyChain, mutableMapOf(), mutableMapOf())

    fun header(key: String, value: Any): JwtBuilder {
        when (key) {
            "kid", "alg", "" -> throw IllegalArgumentException("[$key] has not allow header key name")
        }
        header[key] = value
        return this
    }

    private fun claim(name: String, value: Any, check: Boolean): JwtBuilder {
        if (check) {
            when (name) {
                "exp" -> throw IllegalArgumentException("use setExpire*() instead of claim(\"exp\")")
                "iat" -> throw IllegalArgumentException("use setIssuedAtNow() instead of claim(\"iat\")")
                "" -> throw IllegalArgumentException("name must not empty")
            }
        }
        claims[name] = value
        return this
    }

    fun claim(name: String, value: Any): JwtBuilder =
        claim(name, value, check = true)

    fun encryptClaim(name: String, value: String): JwtBuilder =
        claim(name, keyChain.encrypt(value), check = true)

    fun id(jti: String) =
        claim("jti", jti)

    fun issuer(iss: String) =
        claim("iss", iss)

    fun subject(sub: String) =
        claim("sub", sub)

    fun audience(aud: String) =
        claim("aud", aud)

    fun notBefore(nbf: Date) =
        claim("nbf", nbf.time / 1000)

    fun expire(date: Date) =
        claim("exp", date.time / 1000, check = false)

    fun expireSeconds(seconds: Int) =
        claim("exp", (Date().time / 1000) + seconds, check = false)

    fun expireMinutes(minutes: Int) =
        expireSeconds(minutes * 60)

    fun issuedAt(date: Date) =
        claim("iat", date.time / 1000, check = false)

    fun issuedAtNow() =
        claim("iat", Date().time / 1000, check = false)

    fun build(): String {
        val build = Jwts.builder()
            .setHeaderParam("kid", keyChain.kid)
            .signWith(keyChain.keyPair.private, signatureAlgorithm)
        header.forEach { (n, v) -> build.setHeaderParam(n, v) }
        claims.forEach { (n, v) -> build.claim(n, v) }
        return build.compact()
    }

    init {
        header["kid"] = keyChain.kid
        header["alg"] = signatureAlgorithm

        if (signatureAlgorithm != keyChain.algorithm) {
            throw IllegalArgumentException("signatureAlgorithm and keyChain.algorithm does not match algorithm")
        }
    }
}
