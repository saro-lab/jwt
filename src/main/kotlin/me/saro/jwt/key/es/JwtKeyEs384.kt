package me.saro.jwt.key.es

import me.saro.jwt.key.JwtKey


class JwtKeyEs384(

): JwtKeyEs() {
    override fun algorithm(): String = "ES384"

    override fun validate(jwt: String): Boolean {
        TODO("Not yet implemented")
    }
}