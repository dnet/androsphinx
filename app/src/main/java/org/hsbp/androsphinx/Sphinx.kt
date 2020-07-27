// SPDX-FileCopyrightText: 2019, Andras Veres-Szentkiralyi <vsza@vsza.hu>
// SPDX-License-Identifier: MIT

package org.hsbp.androsphinx

import java.nio.charset.Charset
import java.nio.CharBuffer

const val SPHINX_255_SCALAR_BYTES: Int = 32
const val SPHINX_255_SER_BYTES: Int = 32
const val DECAF_255_SER_BYTES: Int = 32

class Sphinx {
    companion object {
        init {
            System.loadLibrary("sphinx")
        }

        @JvmStatic private external fun challenge(password: ByteArray, blindingFactor: ByteArray, challenge: ByteArray)
        @JvmStatic external fun respond(challenge: ByteArray, secret: ByteArray): ByteArray?
        @JvmStatic private external fun finish(password: ByteArray, blindingFactor: ByteArray, resp: ByteArray): ByteArray?
    }

    class Challenge(pwd: CharArray) : AutoCloseable {
        private val blindingFactor: ByteArray = ByteArray(SPHINX_255_SCALAR_BYTES)
        val challenge: ByteArray = ByteArray(SPHINX_255_SER_BYTES)
        private val passwordBytes = toBytes(pwd)

        init {
            challenge(passwordBytes, blindingFactor, challenge)
        }

        fun finish(response: ByteArray): ByteArray? {
            return finish(passwordBytes, blindingFactor, response)
        }

        override fun close() {
            challenge.fill(0)
        }
    }
}

// SRC: https://stackoverflow.com/a/9670279

private fun toBytes(chars: CharArray): ByteArray {
    val charBuffer = CharBuffer.wrap(chars)
    val byteBuffer = Charset.forName("UTF-8").encode(charBuffer)
    val bytes = byteBuffer.array().sliceArray(byteBuffer.position() until byteBuffer.limit())
    charBuffer.array().fill('\u0000') // clear sensitive data
    byteBuffer.array().fill(0) // clear sensitive data
    return bytes
}
