package me.corite.crypto.rsa

import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import kotlin.experimental.xor

class OptimalAsymmetricEncryptionPadding {
    private fun maskGeneratingFunction(seed:ByteArray, length:Int, hashFunction:MessageDigest):ByteArray {
        var t = byteArrayOf()
        var counter = 0

        do {
            counter++
            val c = getBytes(counter)
            t += hashFunction.digest(seed + c)

        } while (t.size <= length)
        return t.copyOfRange(0,length)
    }


    private fun getBytes(word: Int):ByteArray {
        val mask:UInt = "FF000000".toUInt(16)
        val bytes = ByteArray(4)
        for (i in 0..3) {
            bytes[i] = ((word.toUInt() and (mask shr (8*i))) shr ((3-i)*8)).toByte()
        }
        return bytes
    }

    fun transform(n:BigInteger, m:ByteArray, hashFunction:MessageDigest):ByteArray {
        if (m.size > n.toByteArray().size - 2*hashFunction.digestLength -2) {
            throw IllegalArgumentException("message is too long")
        }
        val l = byteArrayOf()
        val oneByte = byteArrayOf(1)
        val zeroByte = byteArrayOf(0)
        val lHash = hashFunction.digest(l)
        val random = SecureRandom()
        val seed = random.generateSeed(hashFunction.digestLength)

        val psLength = n.toByteArray().size - m.size - 2*hashFunction.digestLength - 2
        val ps = ByteArray(psLength)

        val mgf1 = maskGeneratingFunction(seed, lHash.size+ps.size+oneByte.size+m.size,hashFunction)
        val maskedDB = xorBytes(mgf1, lHash+ps+oneByte+m)

        val mgf2 = maskGeneratingFunction(maskedDB, seed.size, hashFunction)
        val maskedSeed = xorBytes(seed,mgf2)

        return zeroByte + maskedSeed + maskedDB

    }

    fun reverseTransform(transformed:ByteArray, hashFunction: MessageDigest):ByteArray {
        val zeroByte = transformed.copyOfRange(0,1)
        val maskedSeed = transformed.copyOfRange(1,1+hashFunction.digestLength)
        val maskedDB = transformed.copyOfRange(1+hashFunction.digestLength,transformed.size)

        val mgf2 = maskGeneratingFunction(maskedDB, hashFunction.digestLength, hashFunction)
        val seed = xorBytes(maskedSeed,mgf2)
        val mgf1 = maskGeneratingFunction(seed, maskedDB.size, hashFunction)
        val rightInput = xorBytes(mgf1, maskedDB)

        val lHash = rightInput.copyOfRange(0, hashFunction.digestLength)
        val psOneByteAndM = rightInput.copyOfRange(hashFunction.digestLength,rightInput.size)
        val oneByteIndex = getFirst1ByteIndex(psOneByteAndM)
        val ps = psOneByteAndM.copyOfRange(0, oneByteIndex)
        val oneByte = psOneByteAndM.copyOfRange(oneByteIndex, oneByteIndex+1)
        val m = psOneByteAndM.copyOfRange(oneByteIndex+1, psOneByteAndM.size)

        return m
    }

    private fun xorBytes(a1:ByteArray, a2:ByteArray):ByteArray {
        if (a1.size != a2.size) {
            throw IllegalArgumentException("bytearrays have to have the same length")
        }
        val result = ByteArray(a1.size)
        for (i in result.indices) {
            result[i] = a1[i] xor a2[i]
        }
        return result
    }

    private fun getFirst1ByteIndex(array: ByteArray):Int {
        val oneByte:Byte = 1
        for (i in array.indices) {
            if (array[i] == oneByte) {
                return i
            }
        }
        throw IllegalArgumentException()
    }

}