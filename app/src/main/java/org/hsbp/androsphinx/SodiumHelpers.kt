// SPDX-FileCopyrightText: 2019, Andras Veres-Szentkiralyi <vsza@vsza.hu>
// SPDX-License-Identifier: MIT

package org.hsbp.androsphinx

import org.hsbp.androsphinx.Sodium.Companion.genericHash
import java.lang.RuntimeException
import java.nio.ByteBuffer

class SodiumException(message: String) : RuntimeException(message)

const val MASTER_KEY_BYTES = 32

enum class Context(private val value: String) {
    SIGNING("sphinx signing key"),
    ENCRYPTION("sphinx encryption key"),
    SALT("sphinx host salt"),
    PASSWORD("sphinx password context");

    fun foldHash(vararg messages: ByteArray): ByteArray =
        messages.fold(value.toByteArray(), ::genericHash)
}

inline class MasterKey(private val bytes: ByteArray) {
    companion object {
        fun generate(): MasterKey = MasterKey(Sodium.randomBytes(MASTER_KEY_BYTES))

        fun fromByteArray(value: ByteArray): MasterKey {
            require(value.size == MASTER_KEY_BYTES) { "Invalid master key size" }
            return MasterKey(value)
        }

        fun fromByteBuffer(buffer: ByteBuffer): MasterKey {
            val s = MasterKey(ByteArray(MASTER_KEY_BYTES))
            buffer.get(s.bytes)
            return s
        }
    }

    fun contentEquals(other: MasterKey) = other.bytes.contentEquals(bytes)

    fun foldHash(context: Context, vararg messages: ByteArray?): ByteArray =
        context.foldHash(*(listOf(asBytes) + messages.filterNotNull().toList()).toTypedArray())

    val asBytes: ByteArray
        get() = bytes
}

inline class Ed25519PrivateKey(val key: ByteArray) {
    companion object {
        fun fromSeed(seed: ByteArray): Ed25519PrivateKey {
            require(seed.size == CRYPTO_SIGN_SEEDBYTES) { "Invalid seed size" }
            return Ed25519PrivateKey(Sodium.cryptoSignSeedKeypair(seed))
        }
    }

    fun sign(message: ByteArray): ByteArray {
        require(key.size == CRYPTO_SIGN_SECRETKEYBYTES) { "Invalid secret key size" }
        return Sodium.cryptoSignDetached(key, message)
    }

    val publicKey: ByteArray
        get() {
            require(key.size == CRYPTO_SIGN_SECRETKEYBYTES) { "Invalid secret key size" }
            return Sodium.cryptoSignEd25519SkToPk(key)
        }
}

inline class SecretBoxKey(private val key: ByteArray) {
    companion object {
        fun fromByteArray(value: ByteArray): SecretBoxKey {
            require(value.size == CRYPTO_SECRETBOX_XSALSA20POLY1305_KEYBYTES) { "Invalid key size" }
            return SecretBoxKey(value)
        }
    }

    fun encrypt(plainText: ByteArray): ByteArray {
        require(key.size == CRYPTO_SECRETBOX_XSALSA20POLY1305_KEYBYTES) { "Invalid key size" }
        return Sodium.cryptoSecretboxEasy(key, plainText)
    }

    fun decrypt(input: ByteArray): ByteArray {
        require(key.size == CRYPTO_SECRETBOX_XSALSA20POLY1305_KEYBYTES) { "Invalid key size" }
        require(input.size > CRYPTO_SECRETBOX_NONCEBYTES) { "Invalid input size" }
        return Sodium.cryptoSecretboxOpenEasy(key, input) ?: throw SodiumException("Cannot open secretBox")
    }
}