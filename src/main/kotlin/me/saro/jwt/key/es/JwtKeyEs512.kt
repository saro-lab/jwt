package me.saro.jwt.key.es

import me.saro.jwt.key.JwtKey


class JwtKeyEs512(

): JwtKeyEs() {
    override fun algorithm(): String = "ES512"
}