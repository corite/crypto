package me.corite.crypto

import me.corite.crypto.aes128.Main as AES128
import me.corite.crypto.bb84.Main as BB84
import me.corite.crypto.caesar.Main as Caesar
import me.corite.crypto.cbc_mac_ccm.Main as CbcMacCcm
import me.corite.crypto.diffie_hellman.Main as DiffieHellman
import me.corite.crypto.dsa.Main as DSA
import me.corite.crypto.linear_cryptanalysis.Main as LinearCryptanalysis
import me.corite.crypto.rsa.Main as RSA
import me.corite.crypto.sha1.Main as SHA1
import me.corite.crypto.vigenere.Main as Vigenere


fun main() {
    val actions = arrayOf(AES128(), BB84(), Caesar(), CbcMacCcm(), DiffieHellman(), DSA(), LinearCryptanalysis(), RSA(), SHA1(), Vigenere())
    actions.forEach { print(it) }
}

fun print(action:Action) {
    println()
    println()
    println("############################################")
    println("Performing Action '${action.javaClass.name}'")
    println("############################################")
    println()
    println()

    action.main()
}