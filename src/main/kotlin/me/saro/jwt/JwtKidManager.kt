package me.saro.jwt

import me.saro.jwt.core.JwtAlgorithm
import me.saro.jwt.core.JwtKey
import me.saro.jwt.core.JwtIo
import me.saro.jwt.exception.JwtException
import java.util.concurrent.ConcurrentHashMap

class JwtKidManager<KID>(
    private val jwtAlgorithm: JwtAlgorithm,
    private val jwtKeyMap: ConcurrentHashMap<KID, JwtKey>,
    private val newJwtIoKeyPicker: (Map<KID, JwtKey>) -> Pair<KID, JwtKey>
) {

    fun addKey(kid: KID, jwtKey: JwtKey) {
        jwtKeyMap[kid] = jwtKey
    }

    fun delKey(kid: KID?) {
        jwtKeyMap.remove(kid)
    }

    fun delKeyIf(filter: (KID, JwtKey) -> Boolean) {
        for ((kid, key) in jwtKeyMap) {
            if (filter(kid, key)) {
                jwtKeyMap.remove(kid!!)
            }
        }
    }

    fun setKeyMap(map: Map<KID, JwtKey>) {
        val ids = map.keys
        map.forEach { (id, jwtKey) -> addKey(id, jwtKey) }
        delKeyIf { id, _ -> !ids.contains(id) }
    }

    fun createJwtIo() =
        JwtIo.create(jwtAlgorithm.algorithm())

    fun toJwt(jwtIo: JwtIo): String {
        val pair = newJwtIoKeyPicker(jwtKeyMap)
        jwtIo.header("kid", pair.first as Any)
        val body = jwtIo.toJwtBody()
        return body + "." + jwtAlgorithm.signature(pair.second, body)
    }


    fun toJwtIo(jwt: String): JwtIo {
        val jwtIo = JwtIo.parse(jwt)

        val kid = jwtIo.kid()
            ?: throw JwtException("dose not exist kid field")

        @Suppress("UNCHECKED_CAST")
        val key = jwtKeyMap[kid as KID]
            ?: throw JwtException("not found key[kid=$kid]")

        return jwtAlgorithm.verify(key, jwt, jwtIo)
    }
}