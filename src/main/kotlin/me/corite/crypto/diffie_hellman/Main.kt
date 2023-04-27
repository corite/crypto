package me.corite.crypto.diffie_hellman

import me.corite.crypto.Action
import java.math.BigInteger

class Main : Action {
    override fun main() {

        //alice
        val dh = DiffieHellman()
        val (p, g) = dh.generateSuitablePG(500)

        // exchange
        // p and g
        // publicly

        val a = dh.getRandomBigInteger(BigInteger.TWO, p - BigInteger.ONE)
        val A = dh.squareMultiply(g, a, p)

        //bob
        val b = dh.getRandomBigInteger(BigInteger.TWO, p - BigInteger.ONE)
        val B = dh.squareMultiply(g, b, p)

        // exchange
        // A and B
        // publicly

        //alice
        val sOfALice = dh.squareMultiply(B, a, p)

        //bob
        val sOfBob = dh.squareMultiply(A, b, p)


        println(sOfALice == sOfBob)

    }
}