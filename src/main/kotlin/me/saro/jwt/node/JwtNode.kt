package me.saro.jwt.node

import me.saro.jwt.key.JwtVerifyKey
import me.saro.jwt.node.JwtUtils.Companion.DOT_BYTE

open class JwtNode private constructor(
    override val header: Map<String, String>,
    override val payload: Map<String, Any>,
    jwt: ByteArray = ByteArray(0),
    firstDot: Int = -1,
    lastDot: Int = -1,
): JwtReaderSpec(header, payload) {
    private val jwtBody: ByteArray = jwt.copyOfRange(0, lastDot)
    private val jwtSignature: ByteArray = jwt.copyOfRange(lastDot + 1, jwt.size)

    val algorithm: String = header["alg"] ?: ""

    fun verify(key: JwtVerifyKey?): Boolean {
        if (key != null) {
            try {
                expire?.also {
                    if (it.time < System.currentTimeMillis()) {
                        return false
                    }
                }
                notBefore?.also {
                    if (it.time > System.currentTimeMillis()) {
                        return false
                    }
                }
                return key.verify(jwtBody, jwtSignature)
            } catch (e: Exception) { }
        }
        return false
    }
    fun verify(key: (kid: String?) -> JwtVerifyKey): Boolean =
        verify(key(kid))

    fun toBuilder(): JwtBuilder = JwtBuilder(header.toMutableMap(), payload.toMutableMap())

    companion object {
        @JvmStatic
        fun parsePair(jwt: String): Pair<JwtNode?, String?> {
            val jwtByte: ByteArray = jwt.toByteArray()
            val firstDot: Int = jwtByte.indexOf(DOT_BYTE)
            val lastDot: Int = jwtByte.lastIndexOf(DOT_BYTE)

            // firstDot must be not -1
            // lastDot must be not -1 and firstDot must be less than lastDot
            if (firstDot == lastDot) {
                return Pair(null, null)
            }

            val header: Map<String, String> = try {
                JwtUtils.Companion.readTextMap(JwtUtils.Companion.decodeBase64Url(jwtByte.copyOfRange(0, firstDot)))
            } catch (e: Exception) {
                return Pair(null, "$jwt invalid jwt header")
            }

            val payload: Map<String, Any> = try {
                JwtUtils.Companion.readMap(
                    JwtUtils.Companion.decodeBase64Url(
                        jwtByte.copyOfRange(
                            firstDot + 1,
                            lastDot
                        )
                    )
                );
            } catch (e: Exception) {
                return Pair(null, "$jwt invalid jwt payload")
            }

            return Pair(JwtNode(header, payload, jwtByte, firstDot, lastDot), null)
        }
    }
}
