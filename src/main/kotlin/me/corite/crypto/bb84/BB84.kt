package me.corite.crypto.bb84

import kotlin.random.Random
import kotlin.random.nextUInt

class BB84 {

    fun getRandomBits(n:Int):ByteArray {
        val random = Random.Default
        val arr = ByteArray(n)

        return arr.map { random.nextBits(1).toByte() }.toByteArray()
    }

    fun encodeQBits(arr1:ByteArray, arr2: ByteArray):Array<QBit> {
        if (arr1.size != arr2.size) throw IllegalArgumentException()

        return arr1.mapIndexed { i, value -> QBit(value, Basis.fromByte(arr2[i])) }.toTypedArray()
    }

    fun measureQBits(qBits:Array<QBit>, basisArr:ByteArray):ByteArray {
        return qBits.mapIndexed { i, qBit -> qBit.read(Basis.fromByte(basisArr[i])) }.toByteArray()
    }

    fun getCommonBitIndices(arr1: ByteArray, arr2: ByteArray):IntArray {
        return arr1.mapIndexed { i, arr1i -> if(arr1i == arr2[i]) i else -1 }.filter { it != -1 }.sorted().toIntArray()
    }

    fun getRandomIndices(k:Int, n:Int):IntArray {
        if (k>n) throw IllegalArgumentException()

        val random = Random.Default
        val indices = IntArray(k)

        for (i in 0 until k) {
            var randIndex:Int
            do {
                randIndex = (random.nextUInt() % n.toUInt()).toInt()
                //0 <= randIndex < n
                val usedIndices = indices.copyOf(i)
                //all indices so far (not checking the whole array because the elements are initialised to 0, meaning 0 could never be picked)
            } while (usedIndices.contains(randIndex))
            indices[i] = randIndex
        }
        return indices.sorted().toIntArray()
        //sorting is only for convenience, it is not necessary
    }

    fun getBitsAtIndices(arr: ByteArray, indices:IntArray):ByteArray {
        return indices.sorted().map { arr[it] }.toByteArray()
    }

    fun removeBitsAtIndices(arr: ByteArray, indices:IntArray):ByteArray {
        return arr.filterIndexed { i, _ -> !indices.contains(i) }.toByteArray()
    }
}