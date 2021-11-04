package me.saro.jwt.old.io

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
import me.saro.jwt.old.KeyChain
import java.util.*

class JwtReader(
    private val jwt: Jws<Claims>,
    private val keyChain: KeyChain
) {
    @Suppress("UNCHECKED_CAST")
    fun <T> header(key: String): T? =
        jwt.header[key] as T?

    @Suppress("UNCHECKED_CAST")
    fun <T> claim(name: String): T? =
        jwt.body[name] as T?

    val issuer: String? get() = jwt.body.issuer
    val subject: String? get() = jwt.body.subject
    val audience: String? get() = jwt.body.audience
    val notBefore: Date? get() = jwt.body.notBefore
    val id: String? get() = jwt.body.id
    val issuedAt: Date? get() = jwt.body.issuedAt
    val expire: Date? get() = jwt.body.expiration

    fun decryptClaim(name: String): String? =
        jwt.body[name]
            ?.run { keyChain.decrypt(this.toString()) }
}
