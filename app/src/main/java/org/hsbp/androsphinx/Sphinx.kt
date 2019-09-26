package org.hsbp.androsphinx

import java.nio.charset.Charset
import java.nio.CharBuffer
import java.util.Arrays

const val SPHINX_255_SCALAR_BYTES: Int = 32
const val SPHINX_255_SER_BYTES: Int = 32

class Sphinx {
    companion object {
        init {
            System.loadLibrary("sphinx")
        }

        fun finish(password: CharArray, blindingFactor: ByteArray, response: ByteArray): ByteArray {
            return finish(toBytes(password), blindingFactor, response)
        }

        @JvmStatic private external fun challenge(password: ByteArray, blindingFactor: ByteArray, challenge: ByteArray)
        @JvmStatic external fun respond(challenge: ByteArray, secret: ByteArray): ByteArray
        @JvmStatic private external fun finish(password: ByteArray, blindingFactor: ByteArray, resp: ByteArray): ByteArray
    }

    class Challenge(pwd: CharArray) {
        val blindingFactor: ByteArray = ByteArray(SPHINX_255_SCALAR_BYTES)
        val challenge: ByteArray = ByteArray(SPHINX_255_SER_BYTES)

        init {
            challenge(toBytes(pwd), blindingFactor, challenge)
        }
    }
}

// SRC: https://stackoverflow.com/a/9670279

private fun toBytes(chars: CharArray): ByteArray {

    val charBuffer = CharBuffer.wrap(chars)
    val byteBuffer = Charset.forName("UTF-8").encode(charBuffer)
    val bytes = Arrays.copyOfRange(
        byteBuffer.array(),
        byteBuffer.position(), byteBuffer.limit()
    )
    Arrays.fill(charBuffer.array(), '\u0000') // clear sensitive data
    Arrays.fill(byteBuffer.array(), 0.toByte()) // clear sensitive data
    return bytes
}