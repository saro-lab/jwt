package me.saro.jwt.old.keyPair

import java.security.KeyPair

class JwtPsKey(
    override val algorithm: JwtPsAlgorithm,
    override val keyPair: KeyPair,
): JwtKeyPair() {

}
