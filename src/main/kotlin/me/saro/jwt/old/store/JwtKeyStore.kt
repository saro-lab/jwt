package me.saro.jwt.old.store

import me.saro.jwt.old.Jwt
import me.saro.jwt.old.JwtKey
import me.saro.jwt.old.JwtNode
import me.saro.jwt.JwtUtils

interface JwtKeyStore {
    fun exports(): String
    fun getCurrentKey(): JwtKey
    fun findKey(kid: String): JwtKey
    fun createJwt(): JwtNode.Builder = getCurrentKey().createJwt()
    fun parseJwt(jwt: String): JwtNode = Jwt.Companion.parseJwt(jwt) { findKey(it.kid!!) }
    fun getState(): JwtKeyStoreState
    fun getAllKeysForMonitor(): List<JwtKey>
    fun getExpireKeysForMonitor(): List<JwtKey> = getExpireKeysForMonitor(JwtUtils.epochSecond())
    fun getExpireKeysForMonitor(epochSecond: Long): List<JwtKey> = getAllKeysForMonitor().filter { it.expired(epochSecond) }
    fun getNotReadyKeysForMonitor(): List<JwtKey> = getNotReadyKeysForMonitor(JwtUtils.epochSecond())
    fun getNotReadyKeysForMonitor(epochSecond: Long): List<JwtKey> = getAllKeysForMonitor().filter { it.notReady(epochSecond) }
    fun getActiveKeysForMonitor(): List<JwtKey> = getActiveKeysForMonitor(JwtUtils.epochSecond())
    fun getActiveKeysForMonitor(epochSecond: Long): List<JwtKey> = getAllKeysForMonitor().filter { it.ready(epochSecond) && it.notExpired(epochSecond) }
}
