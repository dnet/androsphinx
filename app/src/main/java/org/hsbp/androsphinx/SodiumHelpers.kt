package org.hsbp.androsphinx

import org.libsodium.jni.Sodium
import java.lang.RuntimeException

class SodiumException(message: String) : RuntimeException(message)

fun cryptoSign(message: ByteArray, key: ByteArray): ByteArray {
    val signed = ByteArray(message.size + Sodium.crypto_sign_bytes())
    Sodium.crypto_sign(signed, intArrayOf(signed.size), message, message.size, key)
    return signed
}

fun genericHash(src: ByteArray, key: ByteArray): ByteArray {
    val result = ByteArray(Sodium.crypto_generichash_bytes())
    Sodium.crypto_generichash(result, result.size, src, src.size, key, key.size)
    return result
}

fun secretBox(plainText: ByteArray, key: ByteArray): ByteArray {
    val cipherText = ByteArray(plainText.size + Sodium.crypto_box_macbytes())
    val nonce = randomBytes(Sodium.crypto_secretbox_noncebytes())
    Sodium.crypto_secretbox_easy(cipherText, plainText, plainText.size, nonce, key)
    return nonce + cipherText
}

fun randomBytes(size: Int): ByteArray {
    val result = ByteArray(size)
    Sodium.randombytes(result, result.size)
    return result
}

fun skToPk(sk: ByteArray): ByteArray {
    val result = ByteArray(Sodium.crypto_sign_ed25519_publickeybytes())
    Sodium.crypto_sign_ed25519_sk_to_pk(result, sk)
    return result
}

fun cryptoSignKeyPair(): ByteArray {
    val sk = ByteArray(Sodium.crypto_sign_secretkeybytes())
    val pk = ByteArray(Sodium.crypto_sign_publickeybytes())
    Sodium.crypto_sign_keypair(pk, sk)
    return sk
}

fun cryptoSignOpen(signedMessage: ByteArray, publicKey: ByteArray): ByteArray {
    val buffer = ByteArray(signedMessage.size)
    val msgLen = intArrayOf(buffer.size)
    if (Sodium.crypto_sign_open(buffer, msgLen, signedMessage, signedMessage.size, publicKey) != 0) {
        throw SodiumException("Invalid signature")
    }
    return buffer.sliceArray(0 until msgLen[0])
}

fun secretBoxOpen(cipherText: ByteArray, nonce: ByteArray, key: ByteArray): ByteArray {
    val message = ByteArray(cipherText.size - Sodium.crypto_secretbox_macbytes())
    if (Sodium.crypto_secretbox_open_easy(message, cipherText, cipherText.size, nonce, key) != 0) {
        throw SodiumException("Cannot open secretBox")
    }
    return message
}