package me.saro.jwt.keyPair

import java.security.KeyPair

class JwtEsKey(
    override val algorithm: JwtEsAlgorithm,
    override val keyPair: KeyPair,
): JwtKeyPair() {

}
