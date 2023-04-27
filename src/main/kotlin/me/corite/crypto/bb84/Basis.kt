package me.corite.crypto.bb84
enum class Basis (val value:Byte){
    STANDARD(0), HADAMARD(1);

    companion object {
        fun fromByte(byte: Byte): Basis {
            return if (byte == (0).toByte()) STANDARD else HADAMARD
        }
    }
}