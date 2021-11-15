package me.saro.jwt.core

import java.time.LocalDateTime

interface JwtKey {
    fun stringify(): String
    fun createDateTime(): LocalDateTime
}
