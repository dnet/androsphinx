// SPDX-FileCopyrightText: 2019, Andras Veres-Szentkiralyi <vsza@vsza.hu>
// SPDX-License-Identifier: MIT

package org.hsbp.androsphinx

import java.nio.charset.Charset
import java.nio.CharBuffer

const val SPHINX_255_SCALAR_BYTES: Int = 32
const val SPHINX_255_SER_BYTES: Int = 32
const val DECAF_255_SER_BYTES: Int = 32
const val CRYPTO_GENERICHASH_BYTES: Int = 32
const val CRYPTO_SIGN_SECRETKEYBYTES: Int = 64
const val CRYPTO_SIGN_PUBLICKEYBYTES: Int = 32
const val CRYPTO_SIGN_SEEDBYTES: Int = 32
const val CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES: Int = 32
const val CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES: Int = 24
const val CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES: Int = 16

class Sodium {
    companion object {
        @JvmStatic external fun genericHash(message: ByteArray, salt: ByteArray,
                                            outputLength: Int = CRYPTO_GENERICHASH_BYTES): ByteArray
        @JvmStatic external fun randomBytes(amount: Int): ByteArray
        @JvmStatic external fun cryptoSignSeedKeypair(seed: ByteArray): ByteArray
        @JvmStatic external fun cryptoSignEd25519SkToPk(sk: ByteArray): ByteArray
        @JvmStatic external fun cryptoSignDetached(sk: ByteArray, msg: ByteArray): ByteArray
        @JvmStatic external fun cryptoAeadXchachaPoly1305IetfEasy(msg: ByteArray, ad: ByteArray, key: ByteArray): ByteArray?
        @JvmStatic external fun cryptoAeadXchachaPoly1305IetfOpenEasy(msg: ByteArray, ad: ByteArray, key: ByteArray): ByteArray?
    }
}

class Sphinx {
    companion object {
        @JvmStatic private external fun challenge(password: ByteArray, salt: ByteArray, blindingFactor: ByteArray, challenge: ByteArray)
        @JvmStatic external fun respond(challenge: ByteArray, secret: ByteArray): ByteArray?
        @JvmStatic private external fun finish(password: ByteArray, blindingFactor: ByteArray, salt: ByteArray, resp: ByteArray): ByteArray?
    }

    class Challenge(pwd: CharArray, salt: ByteArray = ByteArray(0)) : AutoCloseable {
        private val blindingFactor: ByteArray = ByteArray(SPHINX_255_SCALAR_BYTES)
        val challenge: ByteArray = ByteArray(SPHINX_255_SER_BYTES)
        private val passwordBytes = toBytes(pwd)

        init {
            challenge(passwordBytes, salt, blindingFactor, challenge)
        }

        fun finish(salt: ByteArray, response: ByteArray): ByteArray? =
            finish(passwordBytes, blindingFactor, salt, response)

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
