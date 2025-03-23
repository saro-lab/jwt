package me.saro.jwt.store

class JwtKeyStoreState(
    val storeType: String,
    val notBeforeKeys: Int,
    val activeKeys: Int,
    val expireKeys: Int,
) {
    override fun toString(): String =
        "$storeType: notBeforeKeys $notBeforeKeys, activeKeys $activeKeys, expireKeys $expireKeys"
}
