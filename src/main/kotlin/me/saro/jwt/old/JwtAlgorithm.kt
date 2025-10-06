package me.saro.jwt.old

import me.saro.jwt.JwtUtils

interface JwtAlgorithm {
    // algorithm
    val algorithmName: String
    val algorithmFullName: String

    // key
    fun newRandomKey(): JwtKey
    fun parseKey(map: Map<String, String>): JwtKey
    fun parseKey(json: String): JwtKey = parseKey(JwtUtils.Companion.readTextMap(json))
    fun parseKeyArray(jsonArray: String): List<JwtKey> =
        JwtUtils.Companion.readTextMapList(jsonArray).map { parseKey(it) }
}
