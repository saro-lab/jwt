package me.saro.jwt.alg.hs

import javax.crypto.Mac

class JwtAlgorithmHs512: JwtAlgorithmHs() {
    override fun getKeyAlgorithm(): String = "HmacSHA512"
    override fun getMac(): Mac = Mac.getInstance(getKeyAlgorithm())
    override fun algorithm(): String = "HS512"
}