@file:OptIn(ExperimentalUnsignedTypes::class)

package me.corite.crypto.rsa

import me.corite.crypto.Action
import java.math.BigInteger
import java.nio.charset.Charset
import java.security.MessageDigest

class Main : Action {
    override fun main() {
        showRsaPart1()
        showRsaPart2()
        showDiffOfSquares()
        showOaep()
    }

    private fun showRsaPart1() {
        println(":::RSA PART I:::")
        val rsa = RivestShamirAdleman()
        val p = BigInteger("6791")
        val q = BigInteger("15679")
        val (e, d) = rsa.calculateED(p, q)
        showEncAndDec(p, q, e, d)

    }

    private fun showRsaPart2() {
        println("\n:::RSA PART II:::")
        val rsa = RivestShamirAdleman()
        //using BigInteger in order to be able to use (almost) arbitrary length numbers
        val p = rsa.getPrime(1024)
        val q = rsa.getPrime(1024)
        val (e, d) = rsa.calculateED(p, q)
        showEncAndDec(p, q, e, d)

    }

    private fun showDiffOfSquares() {
        println("\n:::Difference of Squares:::")

        val p = BigInteger.valueOf(20353)
        val q = BigInteger.valueOf(41851)
        println("chose p=$p and q=$q. Now trying to factorize N=p*q=${p * q}...")
        val dos = DifferenceOfSquares()
        val pAndQ = dos.factorize(p * q)
        println("p= ${pAndQ.first}")
        println("p= ${pAndQ.second}")

    }

    private fun showOaep() {
        println("\n:::OAEP:::")

        val oaep = OptimalAsymmetricEncryptionPadding()
        val originalMessage = "Hello World!"
        println("original message= '$originalMessage'")
        val byteMessage = originalMessage.toByteArray(Charset.defaultCharset())
        val rsa = RivestShamirAdleman()
        val p = rsa.getPrime(1024)
        val q = rsa.getPrime(1024)
        val n = p * q
        val hashFunction = MessageDigest.getInstance("SHA-256")
        val transformed = oaep.transform(n, byteMessage, hashFunction)
        println(
            "transformed message (hex)= '${
                transformed.asUByteArray().joinToString("") { "0".repeat(2 - it.toString(16).length) + it.toString(16) }
            }'"
        )
        val m = oaep.reverseTransform(transformed, hashFunction)
        println("un-transformed message= '${m.toString(Charset.defaultCharset())}'")
    }

    private fun showEncAndDec(p: BigInteger, q: BigInteger, e: BigInteger, d: BigInteger) {
        val rsa = RivestShamirAdleman()
        val n = p * q
        println("p= $p")
        println("q= $q")
        println("e= $e")
        println("d= $d")
        val x = BigInteger.valueOf(42)
        println("encrypting x= $x")
        val y = rsa.encrypt(x, e, n)
        println("encrypted: y= $y")
        println("decrypted: x= ${rsa.decrypt(y, d, n)}")
    }
}