package me.saro.jwt.kotlin.alg

import me.saro.jwt.alg.hs.JwtHs512
import me.saro.jwt.exception.JwtException
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

@DisplayName("[Kotlin] HS512")
class HS512 {
    @Test
    @DisplayName("check jwt.io example")
    fun t1() {
        val exJwtBody = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0"
        val exJwtSign = "VFb0qJ1LRg_4ujbZoRMXnVkUgiuKq5KxWqNdbKq_G9Vvz-S1zZa9LPxtHWKa64zDl2ofkT8F6jBt_K4riU-fPg"
        val secret = "your-512-bit-secret"

        val alg = JwtHs512()
        val key = alg.getJwtKey(secret)

        val newJwtSign = alg.signature(exJwtBody, key)

        Assertions.assertEquals(exJwtSign, newJwtSign)

        println(Assertions.assertDoesNotThrow { alg.toJwtObjectWithVerify("$exJwtBody.$exJwtSign", key) })
        println(Assertions.assertDoesNotThrow { alg.toJwtObjectWithVerify("$exJwtBody.$newJwtSign", key) })

        Assertions.assertThrows(JwtException::class.java) { alg.toJwtObjectWithVerify(exJwtBody + "." + exJwtSign + "1", key) }
        Assertions.assertThrows(JwtException::class.java) { alg.toJwtObjectWithVerify(exJwtBody + "." + newJwtSign + "1", key) }
    }
}