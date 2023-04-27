package me.corite.crypto.caesar

import java.io.File

class FileHandler {
    val filePrefix = "src" + File.separator + "main" + File.separator + "resources" + File.separator

    fun getBytesFromFile(filePath: String): ByteArray {
        return File(filePrefix + filePath).readBytes()
    }
}
