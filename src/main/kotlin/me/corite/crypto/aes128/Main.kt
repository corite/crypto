@file:OptIn(ExperimentalUnsignedTypes::class)

package me.corite.crypto.aes128

import me.corite.crypto.Action
import java.io.File

val filePrefix = "src" + File.separator + "main" + File.separator + "resources" + File.separator

class Main : Action {
    override fun main() {
        println("#".repeat(16) + " AES PART I " + "#".repeat(16))

        val texts1 = getExample(filePrefix + "example1texts")
        val keys1 = getExample(filePrefix + "example1keys")
        prettyPrintI("Example 1", texts1, keys1)

        val texts2 = getExample(filePrefix + "example2texts")
        val keys2 = getExample(filePrefix + "example2keys")
        prettyPrintI("Example 2", texts2, keys2)

        println("#".repeat(16) + " AES PART II " + "#".repeat(16))

        prettyPrintII("Example 1", getAsLongArray(texts1), keys1[0])
        prettyPrintII("Example 1 only first 20 bytes", getAsLongArray(texts1).copyOfRange(0, 20), keys1[0])
    }

    fun prettyPrintI(title: String, texts: Array<UByteArray>, keys: Array<UByteArray>) {
        val encHandler = EncryptionHandler()
        val decHandler = DecryptionHandler()
        println()
        println("-".repeat(16) + " $title " + "-".repeat(16))
        println()
        for (text in texts) {
            println("plain text    : ${text.joinToString("") { it.toString(16) }}")
            val encryptedText = encHandler.encryptChunk(text, keys)
            println("encrypted text: ${encryptedText.joinToString("") { it.toString(16) }}")
            val decryptedText = decHandler.decryptChunk(encryptedText, keys)
            println("decrypted text: ${decryptedText.joinToString("") { it.toString(16) }}")
            println()
        }
    }

    fun prettyPrintII(title: String, text: UByteArray, key: UByteArray) {
        val encHandler = EncryptionHandler()
        val decHandler = DecryptionHandler()
        println()
        println("-".repeat(16) + " $title " + "-".repeat(16))
        println()

        val encrypted = encHandler.encrypt(text, key, CipherMode.ECB)
        println("clear-text: ${text.joinToString(" ") { it.toString(16) }}")
        println("encrypted : ${encrypted.joinToString(" ") { it.toString(16) }}")
        val decrypted = decHandler.decrypt(encrypted, key, CipherMode.ECB)
        println("decrypted : ${decrypted.joinToString(" ") { it.toString(16) }}")
    }

    fun getExample(file: String): Array<UByteArray> {
        val lines = File(file).readLines(Charsets.US_ASCII)
        val lineArray: Array<UByteArray> = Array(lines.size) { UByteArray(16) }
        for (i in lines.indices) {
            lineArray[i] = lines[i].split(" ").map { it.toUByte(16) }.toUByteArray()
        }
        return lineArray
    }

    fun getAsLongArray(matrix: Array<UByteArray>): UByteArray {
        var arr = ubyteArrayOf()

        for (row in matrix) {
            arr += row
        }
        return arr
    }
}