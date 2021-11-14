package me.saro.jwt.old.key

import me.saro.jwt.core.JwtAlgorithm

interface JwtKeyIo {
    fun generate(): JwtAlgorithm
    fun export(jwtAlgorithm: JwtAlgorithm): String
    fun import(keyData: String): JwtAlgorithm
}

/*
override fun export(): String {

    }
 */