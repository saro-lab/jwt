package me.saro.jwt

interface JwtAlgorithm {
    // algorithm
    val algorithmName: String
    val algorithmFullName: String

    // key
    fun newRandomKey(): JwtKey
    fun parseKey(map: Map<String, String>): JwtKey
    fun parseKey(json: String): JwtKey = parseKey(JwtUtils.readTextMap(json))
    fun parseKeyArray(jsonArray: String): List<JwtKey> =
        JwtUtils.readTextMapList(jsonArray).map { parseKey(it) }
}
