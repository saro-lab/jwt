package me.saro.jwt.old.tbd

class Jwt (
    private val body: String,
    private val sign: String,
    private val header: Map<String, Any>,
    private val payload: Map<String, Any>
) {

}