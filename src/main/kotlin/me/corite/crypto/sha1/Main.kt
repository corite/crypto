package me.corite.crypto.sha1

import me.corite.crypto.Action

class Main : Action {
    @ExperimentalUnsignedTypes
    override fun main() {
        val sha1 = SHA1()
        println(sha1.hashToString("".encodeToByteArray().asUByteArray()))
    }
}