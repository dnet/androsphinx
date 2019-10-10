package org.hsbp.androsphinx

import android.util.Base64
import org.libsodium.jni.Sodium
import org.libsodium.jni.SodiumConstants
import java.lang.RuntimeException
import java.nio.ByteBuffer

class SodiumException(message: String) : RuntimeException(message)

const val SALT_BYTES = 32
const val PK_BASE64_FLAGS = Base64.NO_WRAP or Base64.NO_PADDING

interface KeyMaterial {
    val asBytes: ByteArray
}

inline class Salt(private val salt: ByteArray) : KeyMaterial {
    companion object {
        fun generate(): Salt = Salt(randomBytes(SALT_BYTES))

        fun fromByteArray(value: ByteArray): Salt {
            require(value.size == SALT_BYTES) { "Invalid salt size" }
            return Salt(value)
        }

        fun fromByteBuffer(buffer: ByteBuffer): Salt {
            val s = Salt(ByteArray(SALT_BYTES))
            buffer.get(s.salt)
            return s
        }
    }

    override val asBytes: ByteArray
        get() = salt

    fun hash(message: ByteArray): ByteArray {
        val result = ByteArray(Sodium.crypto_generichash_bytes())
        Sodium.crypto_generichash(result, result.size, message, message.size, salt, salt.size)
        return result
    }
}

inline class Ed25519PrivateKey(private val key: ByteArray) : KeyMaterial {
    companion object {
        fun generate(): Ed25519PrivateKey {
            val sk = ByteArray(Sodium.crypto_sign_secretkeybytes())
            val pk = ByteArray(Sodium.crypto_sign_publickeybytes())
            Sodium.crypto_sign_keypair(pk, sk)
            return Ed25519PrivateKey(sk)
        }

        fun fromByteArray(value: ByteArray): Ed25519PrivateKey {
            require(value.size == Sodium.crypto_sign_secretkeybytes()) { "Invalid secret key size" }
            return Ed25519PrivateKey(value)
        }

        fun fromByteBuffer(buffer: ByteBuffer): Ed25519PrivateKey {
            val sk = Ed25519PrivateKey(ByteArray(Sodium.crypto_sign_secretkeybytes()))
            buffer.get(sk.key)
            return sk
        }
    }

    override val asBytes: ByteArray
        get() = key

    fun sign(message: ByteArray): ByteArray {
        require(key.size == Sodium.crypto_sign_secretkeybytes()) { "Invalid secret key size" }
        val signed = ByteArray(message.size + SodiumConstants.SIGNATURE_BYTES)
        Sodium.crypto_sign(signed, intArrayOf(signed.size), message, message.size, key)
        return signed
    }

    val publicKey: Ed25519PublicKey
        get() {
            require(key.size == Sodium.crypto_sign_secretkeybytes()) { "Invalid secret key size" }
            val result = ByteArray(Sodium.crypto_sign_ed25519_publickeybytes())
            Sodium.crypto_sign_ed25519_sk_to_pk(result, key)
            return Ed25519PublicKey(result)
        }

    val asCurve25519PrivateKey: Curve25519PrivateKey
        get() {
            require(key.size == Sodium.crypto_sign_secretkeybytes()) { "Invalid secret key size" }
            val result = ByteArray(Sodium.crypto_box_secretkeybytes())
            Sodium.crypto_sign_ed25519_sk_to_curve25519(result, key)
            return Curve25519PrivateKey(result)
        }
}

inline class Ed25519PublicKey(private val key: ByteArray) : KeyMaterial {
    companion object {
        fun fromBase64(encoded: String): Ed25519PublicKey {
            val decoded = Base64.decode(encoded, PK_BASE64_FLAGS)
            require(decoded.size == Sodium.crypto_sign_publickeybytes()) { "Invalid public key size" }
            return Ed25519PublicKey(decoded)
        }

        fun fromByteBuffer(buffer: ByteBuffer): Ed25519PublicKey {
            val pk = Ed25519PublicKey(ByteArray(Sodium.crypto_sign_publickeybytes()))
            buffer.get(pk.key)
            return pk
        }
    }

    override val asBytes: ByteArray
        get() = key

    val asBase64: String
        get() = Base64.encodeToString(key, PK_BASE64_FLAGS)

    fun verify(signedMessage: ByteArray): ByteArray {
        require(key.size == Sodium.crypto_sign_publickeybytes()) { "Invalid public key size" }
        val buffer = ByteArray(signedMessage.size)
        val msgLen = intArrayOf(buffer.size)
        if (Sodium.crypto_sign_open(buffer, msgLen, signedMessage, signedMessage.size, key) != 0) {
            throw SodiumException("Invalid signature")
        }
        return buffer.sliceArray(0 until msgLen[0])
    }

    val asCurve25519PublicKey: Curve25519PublicKey
        get() {
            require(key.size == Sodium.crypto_sign_publickeybytes()) { "Invalid public key size" }
            val result = ByteArray(Sodium.crypto_box_publickeybytes())
            Sodium.crypto_sign_ed25519_pk_to_curve25519(result, key)
            return Curve25519PublicKey(result)
        }
}

inline class Curve25519PrivateKey(private val key: ByteArray) : KeyMaterial {
    override val asBytes: ByteArray
        get() = key

    companion object {
        fun generate(): Curve25519PrivateKey {
            val sk = ByteArray(SodiumConstants.SECRETKEY_BYTES)
            val pk = ByteArray(SodiumConstants.PUBLICKEY_BYTES)
            Sodium.crypto_box_keypair(pk, sk)
            return Curve25519PrivateKey(sk)
        }

        fun fromByteArray(value: ByteArray): Curve25519PrivateKey {
            require(value.size == SodiumConstants.SECRETKEY_BYTES) { "Invalid secret key size" }
            return Curve25519PrivateKey(value)
        }
    }

    fun unseal(sealedMessage: ByteArray): ByteArray {
        require(key.size == SodiumConstants.SECRETKEY_BYTES) { "Invalid secret key size" }
        require(sealedMessage.size > SodiumConstants.SEAL_BYTES) { "Invalid input size" }
        val message = ByteArray(sealedMessage.size - SodiumConstants.SEAL_BYTES)
        if (Sodium.crypto_box_seal_open(message, sealedMessage, sealedMessage.size, publicKey.asBytes, key) != 0) {
            throw SodiumException("Cannot open sealedBox")
        }
        return message
    }

    @Suppress("WeakerAccess")
    val publicKey: Curve25519PublicKey
        get() {
            require(key.size == SodiumConstants.SECRETKEY_BYTES) { "Invalid secret key size" }
            val pk = ByteArray(SodiumConstants.PUBLICKEY_BYTES)
            Sodium.crypto_scalarmult_base(pk, key)
            return Curve25519PublicKey(pk)
        }
}

inline class Curve25519PublicKey(private val key: ByteArray) : KeyMaterial {
    override val asBytes: ByteArray
        get() = key

    companion object {
        fun fromByteArray(value: ByteArray): Curve25519PublicKey {
            require(value.size == SodiumConstants.PUBLICKEY_BYTES) { "Invalid public key size" }
            return Curve25519PublicKey(value)
        }
    }

    fun seal(message: ByteArray): ByteArray {
        require(key.size == SodiumConstants.PUBLICKEY_BYTES) { "Invalid public key size" }
        val sealed = ByteArray(message.size + SodiumConstants.SEAL_BYTES)
        Sodium.crypto_box_seal(sealed, message, message.size, key)
        return sealed
    }
}

inline class SecretBoxKey(private val key: ByteArray) {
    companion object {
        fun fromByteArray(value: ByteArray): SecretBoxKey {
            require(value.size == SodiumConstants.XSALSA20_POLY1305_SECRETBOX_KEYBYTES) { "Invalid key size" }
            return SecretBoxKey(value)
        }
    }

    fun encrypt(plainText: ByteArray): Pair<ByteArray, ByteArray> {
        require(key.size == SodiumConstants.XSALSA20_POLY1305_SECRETBOX_KEYBYTES) { "Invalid key size" }
        val cipherText = ByteArray(plainText.size + SodiumConstants.MAC_BYTES)
        val nonce = randomBytes(SodiumConstants.NONCE_BYTES)
        Sodium.crypto_secretbox_easy(cipherText, plainText, plainText.size, nonce, key)
        return nonce to cipherText
    }

    fun decrypt(input: ByteArray): ByteArray {
        require(key.size == SodiumConstants.XSALSA20_POLY1305_SECRETBOX_KEYBYTES) { "Invalid key size" }
        require(input.size > SodiumConstants.NONCE_BYTES) { "Invalid input size" }
        val cipherText = input.sliceArray(SodiumConstants.NONCE_BYTES until input.size)
        val message = ByteArray(cipherText.size - SodiumConstants.MAC_BYTES)
        if (Sodium.crypto_secretbox_open_easy(message, cipherText, cipherText.size, input, key) != 0) {
            throw SodiumException("Cannot open secretBox")
        }
        return message
    }
}

fun Pair<Curve25519PublicKey, Curve25519PrivateKey>.decrypt(input: ByteArray): ByteArray {
    require(input.size > SodiumConstants.NONCE_BYTES + SodiumConstants.MAC_BYTES) { "Invalid input size" }
    val box = input.copyOfRange(SodiumConstants.NONCE_BYTES, input.size)
    val plain = ByteArray(box.size - SodiumConstants.MAC_BYTES)
    if (Sodium.crypto_box_open_easy(plain, box, box.size, input, this.first.asBytes, this.second.asBytes) != 0) {
        throw SodiumException("Cannot open cryptoBox")
    }
    return plain
}

fun Pair<Curve25519PrivateKey, Curve25519PublicKey>.encrypt(input: ByteArray): ByteArray {
    val nonce = randomBytes(SodiumConstants.NONCE_BYTES)
    val ciphertext = ByteArray(input.size + SodiumConstants.MAC_BYTES)
    Sodium.crypto_box_easy(ciphertext, input, input.size, nonce, this.second.asBytes, this.first.asBytes)
    return nonce + ciphertext
}

fun randomBytes(size: Int): ByteArray {
    val result = ByteArray(size)
    Sodium.randombytes(result, result.size)
    return result
}