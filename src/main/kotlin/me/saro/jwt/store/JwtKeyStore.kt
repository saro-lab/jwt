package me.saro.jwt.store

import me.saro.jwt.Jwt
import me.saro.jwt.JwtKey
import me.saro.jwt.JwtNode
import me.saro.jwt.JwtUtils

interface JwtKeyStore {
    fun exports(): String
    fun getCurrentKey(): JwtKey
    fun findKey(kid: String): JwtKey
    fun createJwt(): JwtNode.Builder = getCurrentKey().createJwt()
    fun parseJwt(jwt: String): JwtNode = Jwt.parseJwt(jwt) { findKey(it.kid!!) }
    fun getAllKeysForMonitor(): List<JwtKey>
    fun getExpireKeysForMonitor(): List<JwtKey> = getExpireKeysForMonitor(JwtUtils.epochSecond())
    fun getExpireKeysForMonitor(epochSecond: Long): List<JwtKey> = getAllKeysForMonitor().filter { it.expired(epochSecond) }
    fun getNotReadyKeysForMonitor(): List<JwtKey> = getNotReadyKeysForMonitor(JwtUtils.epochSecond())
    fun getNotReadyKeysForMonitor(epochSecond: Long): List<JwtKey> = getAllKeysForMonitor().filter { it.notReady(epochSecond) }
    fun getActiveKeysForMonitor(): List<JwtKey> = getActiveKeysForMonitor(JwtUtils.epochSecond())
    fun getActiveKeysForMonitor(epochSecond: Long): List<JwtKey> = getAllKeysForMonitor().filter { it.ready(epochSecond) && it.notExpired(epochSecond) }
}
