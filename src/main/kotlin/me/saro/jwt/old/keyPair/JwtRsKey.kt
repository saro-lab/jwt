package me.saro.jwt.old.keyPair

import java.security.KeyPair

class JwtRsKey(
    override val algorithm: JwtRsAlgorithm,
    override val keyPair: KeyPair,
): JwtKeyPair() {

}
