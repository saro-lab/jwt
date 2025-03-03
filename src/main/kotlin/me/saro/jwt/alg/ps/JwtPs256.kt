package me.saro.jwt.alg.ps

import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

class JwtPs256 internal constructor(): JwtPs() {
    override val algorithm: String = "PS256"
    override fun getSignature(): Signature = Signature.getInstance("RSASSA-PSS")
        .apply { setParameter(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)) }
}