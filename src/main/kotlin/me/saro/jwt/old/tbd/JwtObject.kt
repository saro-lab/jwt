package me.saro.jwt.old.tbd

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import me.saro.jwt.JwtException
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.*

class JwtObject private constructor(
    private val body: String,
    private val sign: String,
    private val header: Map<String, Object>,
    private val payload: Map<String, Object>,
) {
    companion object {
        private val base64Decoder = Base64.getUrlDecoder()
        private val base64EncoderP = Base64.getEncoder()
        private val base64EncoderWP = Base64.getUrlEncoder().withoutPadding()
        private val objectMapper = jacksonObjectMapper()

        fun parse(jwt: String) {
            val part = jwt.split(".")
            if (part.size != 3) {
                throw JwtException("there is not jwt format: $jwt")
            }

            val body = jwt.substring(0, jwt.lastIndexOf('.'))
            val sign = part[1]
            var header = JwtConverter.toMap(part[0])
            var payload = JwtConverter.toMap(part[1])

            println("body: $body")
            println("sign: $sign")
            println("header: $body")
            println("payload: $body")

            val kp = KeyPairGenerator.getInstance("EC")
                .apply { initialize(ECGenParameterSpec("secp256r1")) }
                .genKeyPair()


            val public = base64EncoderP.encodeToString(kp.public.encoded)
            val private = base64EncoderP.encodeToString(kp.private.encoded)
            println("public: $public")
            println("private: $private")

            val sign2 = Signature.getInstance("SHA256withECDSAinP1363Format")
                .apply {
                    initSign(kp.private)
                    update(body.toByteArray())
                }
                .sign()
                .run { base64EncoderWP.encodeToString(this) }


            println("sign2: $sign2")
            println("signb: $body.$sign2")

            val verify = Signature.getInstance("SHA256withECDSAinP1363Format")
                .apply {
                    initVerify(kp.public)
                    update(body.toByteArray())
                }
                .verify(base64Decoder.decode(sign2))

            println("verify: $verify")
        }
    }

    fun <T> header(name: String): T? = header[name] as T?
    fun <T> claim(name: String): T? = payload[name] as T?

    val kid: String? get() = header("kid")
    val algorithm: JwtAlgorithm get() = JwtAlgorithm.parse(header("alg"))

    val issuer: String? get() = claim("iss")
    val subject: String? get() = claim("sub")
    val audience: String? get() = claim("aud")
    val id: String? get() = claim("jti")
    val notBefore: Long? get() = claim<Long?>("nbf")?.toString()?.toLong()
    val issuedAt: Long? get() = claim<Long?>("iat")?.toString()?.toLong()
    val expire: Long? get() = claim<Long?>("exp")?.toString()?.toLong()

    val isValid: Boolean get() = try { verify(); true } catch (e: Exception) { false }

    @Throws(JwtException::class)
    fun verify() {
        if ((System.currentTimeMillis() / 1000L) > (expire ?: throw JwtException("expire not exists"))) {
            throw JwtException("expired not exists")
        }
    }
}

fun main() {
    JwtObject.parse("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA")
}
