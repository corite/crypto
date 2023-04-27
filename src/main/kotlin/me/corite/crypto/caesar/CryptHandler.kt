package me.corite.crypto.caesar



class CryptHandler {
    fun getKey(encryptedText: ByteArray, mostFrequentDecryptedByte: Byte): Int {
        val byteFrequencyMap = getByteFrequencyMap(encryptedText)
        val mostFrequentEncryptedByte = getMostFrequentByte(byteFrequencyMap)
        return (mostFrequentEncryptedByte - mostFrequentDecryptedByte + 128) % 128
        //adding 128 before modulo because java thinks p.e -2 % 10 = -2 != 8
    }

    /**
     * @param encryptedText the text to analyse
     * @return a map with each byte of the text as a key and the frequency in which it occurs in the text as value
     */
    private fun getByteFrequencyMap(encryptedText: ByteArray): Map<Byte, Double> {
        val distinctBytes = encryptedText.distinct().toTypedArray()
        //gets the distinct bytes from the text, so that we can put it in the frequency-map later
        val absFrequencyMap = distinctBytes.groupingBy { it }.eachCount()
        val map = mutableMapOf<Byte, Double>()
        absFrequencyMap.entries.forEach { map[it.key] = it.value.toDouble() / encryptedText.size }
        return map
    }

    private fun getMostFrequentByte(byteFrequencyMap: Map<Byte, Double>): Byte {
        return byteFrequencyMap.entries.maxByOrNull { it.value }!!.key
        //get the first entry since it is the most common one
    }

    fun decrypt(byteArray: ByteArray, key: Int): ByteArray {
        //adding 128 before modulo because java thinks p.e -2 % 10 = -2 != 8
        return byteArray.map { ((it - key + 128) % 128).toByte() }.toByteArray()
    }

    fun asString(byteArray: ByteArray): String {
        //Convert all bytes to characters end concatenate them to a String
        return byteArray.joinToString { it.toString() }
    }
}
