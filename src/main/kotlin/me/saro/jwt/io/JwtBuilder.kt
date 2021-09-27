package me.saro.jwt.io

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import me.saro.jwt.model.ClaimName
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

    fun claim(name: ClaimName, value: Any): JwtBuilder =
        claim(name.value, value, check = true)

    fun encryptClaim(name: String, value: String): JwtBuilder =
        claim(name, keyChain.encrypt(value), check = true)

    fun encryptClaim(name: ClaimName, value: String): JwtBuilder =
        claim(name.value, keyChain.encrypt(value), check = true)

    fun setIssuedAtNow() =
        claim("iat", Date().time / 1000, check = false)

    fun setExpireSeconds(seconds: Int) =
        claim("exp", (Date().time / 1000) + seconds, check = false)

    fun setExpireMinutes(minutes: Int) =
        setExpireSeconds(minutes * 60)

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
