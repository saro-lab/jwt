package me.saro.jwt.old.key.es


class JwtKeyEs384(

): JwtAlgorithmEs() {
    override fun algorithm(): String = "ES384"

    override fun validate(jwt: String): Boolean {
        TODO("Not yet implemented")
    }
}