package me.saro.jwt.alg.hs

import javax.crypto.Mac

class JwtAlgorithmHs256: JwtAlgorithmHs() {
    override fun getKeyAlgorithm(): String = "HmacSHA256"
    override fun getMac(): Mac = Mac.getInstance(getKeyAlgorithm())
    override fun algorithm(): String = "HS256"
}