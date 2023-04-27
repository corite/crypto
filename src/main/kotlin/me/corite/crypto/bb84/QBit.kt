package me.corite.crypto.bb84

import kotlin.random.Random

class QBit (private val value:Byte, private val basis: Basis) {
    init {
        if (!(value == (0).toByte() || value == (1).toByte())) throw IllegalArgumentException()
    }

    fun read(readBasis: Basis):Byte {
        return if (basis == readBasis) {
            value
        } else {
            val random = Random.Default
            return random.nextBits(1).toByte()
        }

    }
}