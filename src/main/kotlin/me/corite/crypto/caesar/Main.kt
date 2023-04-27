package me.corite.crypto.caesar

import me.corite.crypto.Action

class Main : Action {
    override fun main() {
        val fileHandler = FileHandler()
        val encryptedBytes = fileHandler.getBytesFromFile("LoremIpsumEncrypted.txt")
        val cryptHandler = CryptHandler()
        val key = cryptHandler.getKey(encryptedBytes, ' '.code.toByte())
        println("Key: $key")
        val decryptedBytes = cryptHandler.decrypt(encryptedBytes, key)
        println("Decrypted Text: " + cryptHandler.asString(decryptedBytes))
    }
}
