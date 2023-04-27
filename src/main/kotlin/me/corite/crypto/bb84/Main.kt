package me.corite.crypto.bb84

import me.corite.crypto.Action

class Main : Action {
    override fun main() {
        val n = 64
        val k = 8
        val bb84 = BB84()

//Alice
        val a1 = bb84.getRandomBits(n)
        val a2 = bb84.getRandomBits(n)
        println("a-value bits: ${a1.toStr()}")
        println("a-basis bits: ${a2.toStr()}")

        val aQBits = bb84.encodeQBits(a1, a2)

//Bob
        val b2 = bb84.getRandomBits(n)
        val b1 = bb84.measureQBits(aQBits, b2)
        println("b-basis bits: ${b2.toStr()}")
        println("b-value bits: ${b1.toStr()}")

//Both
        val commonIndices = bb84.getCommonBitIndices(a2, b2)
        val compareIndices = bb84.getRandomIndices(k, commonIndices.size)
        println("common bit indices: ${commonIndices.toStr()}")
        println("key-indices to compare: ${compareIndices.toStr()}")

//Alice
        val aKeyBits = bb84.getBitsAtIndices(a1, commonIndices)
        val aCompareBits = bb84.getBitsAtIndices(aKeyBits, compareIndices)
        val aKeyActual = bb84.removeBitsAtIndices(aKeyBits, compareIndices)

//Bob
        val bKeyBits = bb84.getBitsAtIndices(b1, commonIndices)
        val bCompareBits = bb84.getBitsAtIndices(bKeyBits, compareIndices)
        val bKeyActual = bb84.removeBitsAtIndices(bKeyBits, compareIndices)




        println("compare-bits are equal: ${aCompareBits.contentEquals(bCompareBits)}")
        println("a-key: ${aKeyBits.toStr()}")
        println("b-key: ${bKeyBits.toStr()}")
        println("a-key without compare bits: ${aKeyActual.toStr()}")
        println("b-key without compare bits: ${bKeyActual.toStr()}")
    }

    private fun ByteArray.toStr(): String {
        return this.joinToString(", ") { it.toString(2) }
    }

    private fun IntArray.toStr(): String {
        return this.joinToString(", ") { it.toString(10) }
    }
}