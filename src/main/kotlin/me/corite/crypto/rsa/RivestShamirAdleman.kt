package me.corite.crypto.rsa

import java.lang.IllegalArgumentException
import java.math.BigInteger
import java.security.SecureRandom

class RivestShamirAdleman {

    private fun squareMultiply(xNum:BigInteger, exponent:BigInteger, modulus:BigInteger):BigInteger {
        // BigInteger.modPow() would probably do the trick too (though I don't know how exactly it is implemented),
        // but since it is part of the exercise this is the implementation "from scratch"
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

    private fun eeA(a:BigInteger, b:BigInteger):Array<BigInteger> {
        // this could also be done by using the built-in BigInteger.modInverse() function
        var r0 = a; var r1 = b
        var (k,s0,s1,t0,t1) = listOf( BigInteger.ZERO, BigInteger.ONE, BigInteger.ZERO, BigInteger.ZERO, BigInteger.ONE )

        do {
            k++
            val qk = r0 / r1
            val rkTmp = r1
            r1 = r0 - qk*rkTmp
            val skTmp = s1
            s1 = s0 - qk*skTmp
            val tkTmp = t1
            t1 = t0 - qk*tkTmp

            r0 = rkTmp
            s0 = skTmp
            t0 = tkTmp

        } while (r1 != BigInteger.ZERO)

        return arrayOf(r0,s0,t0)
    }

    fun encrypt(x:BigInteger, e:BigInteger, n:BigInteger):BigInteger {
        return squareMultiply(x,e,n)
    }

    fun decrypt(y:BigInteger, d:BigInteger, n:BigInteger):BigInteger {
        return squareMultiply(y,d,n)
    }

    fun calculateED(p:BigInteger, q:BigInteger):Pair<BigInteger, BigInteger> {
        val phiOfN = (p - BigInteger.ONE) * (q - BigInteger.ONE)
        do {
            val e = getRandomBigInteger(BigInteger.TWO, phiOfN- BigInteger.ONE)
            val res = eeA(e,phiOfN)
            if (res[0] == BigInteger.ONE) {// e has to be relatively prime to phi of n
                return Pair(e, res[1].mod(phiOfN))
            }
        } while (true)
    }
    fun getPrime(length:Int):BigInteger {
        var isPrime = false
        val random = SecureRandom()
        val z = BigInteger(length,random)
        val init = z * BigInteger.valueOf(30)
        var n:BigInteger
        for (j in 0..200) {
            for (i in getSomePrimes()) {
                n = init + BigInteger.valueOf(i.toLong())+ BigInteger.valueOf(j.toLong())*BigInteger.valueOf(30)
                for (test in 1..40) {
                    isPrime = testMillerRabin(n)
                    if (!isPrime) break
                }
                if (isPrime) return n
            }
        }
        throw IllegalArgumentException()
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

    private fun getRandomBigInteger(min:BigInteger, max:BigInteger):BigInteger {
        val random = SecureRandom()
        var result:BigInteger
        do {
            result = BigInteger(max.bitLength(), random)
        } while (result < min || result > max)

        return result
    }


}