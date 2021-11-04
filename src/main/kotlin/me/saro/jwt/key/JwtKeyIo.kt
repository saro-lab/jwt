package me.saro.jwt.key

interface JwtKeyIo {
    fun generate(): JwtKey
    fun export(jwtKey: JwtKey): String
    fun import(keyData: String): JwtKey
}

/*
override fun export(): String {

    }
 */