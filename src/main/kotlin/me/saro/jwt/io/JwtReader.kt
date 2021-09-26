package me.saro.jwt.io

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
import me.saro.jwt.model.ClaimName
import me.saro.jwt.model.KeyChain

class JwtReader(
    private val jwt: Jws<Claims>,
    private val keyChain: KeyChain
) {
    fun header(key: String): Any? =
        jwt.header[key]

    fun claim(name: String): Any? =
        jwt.body[name]

    fun claim(name: ClaimName): Any? =
        claim(name.value)

    fun decryptClaim(name: String): Any? =
        jwt.body[name]
            ?.run { keyChain.decrypt(this.toString()) }

    fun decryptClaim(name: ClaimName): Any? =
        decryptClaim(name.value)
}
