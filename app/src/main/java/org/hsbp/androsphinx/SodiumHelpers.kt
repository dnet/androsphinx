// SPDX-FileCopyrightText: 2019, Andras Veres-Szentkiralyi <vsza@vsza.hu>
// SPDX-License-Identifier: MIT

package org.hsbp.androsphinx

import org.hsbp.androsphinx.Sodium.Companion.genericHash
import java.lang.RuntimeException
import java.nio.ByteBuffer

class SodiumException(message: String) : RuntimeException(message)

const val MASTER_KEY_BYTES = 32

enum class DerivationContext(private val value: String, private val hashLength: Int = CRYPTO_GENERICHASH_BYTES) {
    SIGNING("sphinx signing key"),
    ENCRYPTION("sphinx encryption key"),
    SALT("sphinx host salt"),
    CHECK_DIGIT("sphinx check digit context", hashLength = 1),
    PASSWORD("sphinx password context");

    fun foldHash(vararg messages: ByteArray): ByteArray =
        messages.fold(value.toByteArray()) { acc, message -> genericHash(acc, message, hashLength) }
}

@JvmInline
value class MasterKey(private val bytes: ByteArray) {
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

    fun foldHash(context: DerivationContext, vararg messages: ByteArray?): ByteArray =
        context.foldHash(*(listOf(asBytes) + messages.filterNotNull().toList()).toTypedArray())

    val asBytes: ByteArray
        get() = bytes
}

@JvmInline
value class Ed25519PrivateKey(val key: ByteArray) {
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

private val VERSION: ByteArray = byteArrayOf(0)

@JvmInline
value class AeadKey(private val key: ByteArray) {
    companion object {
        fun fromByteArray(value: ByteArray): AeadKey {
            require(value.size == CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES) { "Invalid key size" }
            return AeadKey(value)
        }
    }

    fun encrypt(plainText: ByteArray): ByteArray {
        require(key.size == CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES) { "Invalid key size" }
        return VERSION + Sodium.cryptoAeadXchachaPoly1305IetfEasy(plainText, VERSION, key)!!
    }

    fun decrypt(input: ByteArray): Pair<Byte, ByteArray> {
        require(key.size == CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES) { "Invalid key size" }
        require(input.size > CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES) { "Invalid input size" }
        val ciphertext = input.sliceArray(1 until input.size)
        val version = input[0]
        if (version != VERSION[0]) throw UnknownVersionException()
        val plaintext = Sodium.cryptoAeadXchachaPoly1305IetfOpenEasy(ciphertext, byteArrayOf(version), key) ?: throw SodiumException("Cannot decrypt AEAD")
        return version to plaintext
    }
}

class UnknownVersionException : RuntimeException()