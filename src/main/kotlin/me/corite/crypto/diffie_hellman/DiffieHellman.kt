package me.corite.crypto.diffie_hellman

import java.math.BigInteger
import java.security.SecureRandom

class DiffieHellman {


    fun generateSuitablePG(length:Int):Pair<BigInteger, BigInteger> {
        val p = generateSuitableP(length)
        val g = getRandomBigInteger(BigInteger.TWO, p- BigInteger.ONE)
        return Pair(p,g)
    }

    private fun generateSuitableP(length: Int):BigInteger{
        var q:BigInteger
        var p:BigInteger
        do {
            q = getPrime(length)
            p = BigInteger.TWO * q + BigInteger.ONE
        } while (!isProbablePrime(p))
        return p
    }


    private fun getPrime(length:Int): BigInteger {
        val random = SecureRandom()
        val z = BigInteger(length,random)
        val init = z * BigInteger.valueOf(30)
        var n:BigInteger
        for (j in 0..200) {
            for (i in getSomePrimes()) {
                n = init + BigInteger.valueOf(i.toLong())+ BigInteger.valueOf(j.toLong())*BigInteger.valueOf(30)
                if (isProbablePrime(n)) {
                    return n
                }
            }
        }
        throw IllegalArgumentException()
    }

    private fun isProbablePrime(num:BigInteger):Boolean {
        for (i in 1..20) {
            if (!testMillerRabin(num)) {
                return false
            }
        }
        return true
    }

    private fun getSomePrimes():IntArray {
        return intArrayOf(1, 7, 11, 13, 17, 19, 23, 29)
    }

    private fun testMillerRabin(n: BigInteger): Boolean {
        val (k,m) = getKM(n)
        val a = getRandomBigInteger(BigInteger.TWO, n - BigInteger.ONE)

        var b = squareMultiply(a, m, n)
        if (b % n == BigInteger.ONE) {
            return true
        }
        for (i in 1..k) {
            if (b % n == n-BigInteger.ONE || b % n ==-BigInteger.ONE) {
                return true
            } else {
                b = squareMultiply(b, BigInteger.TWO, n)
            }
        }
        return false
    }

    private fun getKM(n:BigInteger):Pair<Int, BigInteger> {
        val n1 = n - BigInteger.ONE
        var k = 0

        while (n1.testBit(k)) {
            k++
        }
        return Pair(k+1, n1.shiftRight(k+1))
    }

    fun getRandomBigInteger(min:BigInteger, max:BigInteger):BigInteger {
        val random = SecureRandom()
        var result:BigInteger
        do {
            result = BigInteger(max.bitLength(), random)
        } while (result < min || result > max)

        return result
    }

    fun squareMultiply(xNum:BigInteger, exponent:BigInteger, modulus:BigInteger):BigInteger {
        var x = xNum
        var y = BigInteger.ONE
        val r = exponent.bitLength()
        for (i in 0..r) {
            if (exponent.testBit(i)) {
                y = y*x % modulus
            }
            x = x.pow(2) % modulus
        }

        return y
    }



}