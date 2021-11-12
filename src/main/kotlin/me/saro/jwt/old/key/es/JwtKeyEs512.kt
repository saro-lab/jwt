package me.saro.jwt.old.key.es


class JwtKeyEs512(

): JwtAlgorithmEs() {
    override fun algorithm(): String = "ES512"
}