package me.corite.crypto.rsa

import java.math.BigInteger

class DifferenceOfSquares {


    fun factorize(N:BigInteger):Pair<BigInteger, BigInteger> {
        var u = N.sqrt()
        while (!isSquare(u.pow(2)-N)) {
           u++
        }
        val w = (u.pow(2)-N).sqrt()
        return Pair(u+w,u-w)
    }
    private fun isSquare(x:BigInteger):Boolean {
        return if (x < BigInteger.ZERO) {
            false
        } else {
            x.sqrt().pow(2) == x
        }
    }
}