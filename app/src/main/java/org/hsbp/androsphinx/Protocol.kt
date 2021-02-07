// SPDX-FileCopyrightText: 2019, Andras Veres-Szentkiralyi <vsza@vsza.hu>
// SPDX-License-Identifier: MIT

package org.hsbp.androsphinx

import java.io.InputStream
import java.lang.RuntimeException
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.net.ssl.SSLSocketFactory

const val SIZE_MASK: Int = 0x7F
const val RULE_SHIFT: Int = 7
const val RULE_BYTES_LENGTH: Int = 2
const val AUTH_NONCE_BYTES: Int = 32
const val ENCRYPTED_RULE_LENGTH: Int = CRYPTO_SECRETBOX_XSALSA20POLY1305_NONCEBYTES + CRYPTO_SECRETBOX_XSALSA20POLY1305_MACBYTES + RULE_BYTES_LENGTH

class Protocol {
    enum class Command(val code: Byte, val requiresAuth: Boolean = true, val writeRule: Boolean = false) {
        CREATE(0x00, requiresAuth = false, writeRule = true), READ(0x33), UNDO(0x55, writeRule = true),
        GET(0x66, requiresAuth = false), COMMIT(0x99.toByte(), writeRule = true),
        CHANGE(0xAA.toByte()), WRITE(0xCC.toByte()), DELETE(0xFF.toByte());

        fun <T> connect(cs: CredentialStore, password: CharArray, id: ByteArray, body: (Socket, Sphinx.Challenge, ByteArray) -> T): T =
            cs.createSocket().use { socket ->
                Sphinx.Challenge(password).use { challenge ->
                    val message = ByteBuffer.allocate(DECAF_255_SER_BYTES + CRYPTO_GENERICHASH_BYTES + 1)
                    message.put(code)
                    message.put(id)
                    message.put(challenge.challenge)
                    socket.getOutputStream().write(message.array())
                    val rwd = challenge.finish(id, socket.getInputStream())
                    if (requiresAuth) cs.auth(socket, id, rwd)
                    return body(socket, challenge, rwd)
                }
            }

        @Suppress("UsePropertyAccessSyntax")
        fun execute(realm: Realm, password: CharArray, cs: CredentialStore, callback: PasswordCallback,
                    createRule: Pair<Set<CharacterClass>, Int>? = null) {
            val hostId = realm.hash(cs)

            val derived = connect(cs, password, hostId) { s, challenge, oldRwd ->
                val sis = s.getInputStream()
                val newRwd = if (requiresAuth) challenge.finish(hostId, sis) else oldRwd

                val (rule, size) = if (createRule == null) {
                    val ruleBytes = cs.getSealKey().decrypt(sis.readExactly(ENCRYPTED_RULE_LENGTH))
                    val combined =
                        ByteBuffer.wrap(ruleBytes).order(ByteOrder.BIG_ENDIAN).getShort()
                            .toInt()
                    val size = combined and SIZE_MASK
                    val rule = CharacterClass.parse((combined shr RULE_SHIFT).toByte())
                    rule to size
                } else createRule

                if (writeRule) {
                    sendRule(s, rule, size, cs.getSealKey(), cs.getSignKey(hostId, newRwd))
                }

                if (createRule != null) {
                    updateUserList(s, cs, realm) { users -> users + realm.username }
                }

                CharacterClass.derive(Context.PASSWORD.foldHash(newRwd), rule, size)
            }

            callback.passwordReceived(derived)
        }
    }

    data class Realm(val username: String, val hostname: String) {
        fun hash(cs: CredentialStore) = org.hsbp.androsphinx.Sodium.genericHash("$username|$hostname".toByteArray(), cs.key.foldHash(Context.SALT))

        val withoutUser: Realm
            get() = Realm(username = "", hostname = hostname)
    }

    class ServerFailureException : RuntimeException()

    interface CredentialStore {
        val key: MasterKey
        val host: String
        val port: Int
    }

    interface PasswordCallback {
        fun passwordReceived(password: CharArray)
    }

    companion object {

        fun create(password: CharArray, realm: Realm, charClasses: Set<CharacterClass>,
                   cs: CredentialStore, callback: PasswordCallback, size: Int = 0) {
            require(charClasses.isNotEmpty()) { "At least one character class must be allowed." }
            Command.CREATE.execute(realm, password, cs, callback, charClasses to size)
        }

        fun get(password: CharArray, realm: Realm, cs: CredentialStore, callback: PasswordCallback) {
            Command.GET.execute(realm, password, cs, callback)
        }

        fun change(password: CharArray, realm: Realm, cs: CredentialStore, callback: PasswordCallback) {
            Command.CHANGE.execute(realm, password, cs, callback)
        }

        fun commit(password: CharArray, realm: Realm, cs: CredentialStore, callback: PasswordCallback) {
            Command.COMMIT.execute(realm, password, cs, callback)
        }

        fun undo(password: CharArray, realm: Realm, cs: CredentialStore, callback: PasswordCallback) {
            Command.UNDO.execute(realm, password, cs, callback)
        }

        fun delete(password: CharArray, realm: Realm, cs: CredentialStore) {
            Command.DELETE.connect(cs, password, realm.hash(cs)) { s, _, _ ->
                updateUserList(s, cs, realm) { users -> if (users.isEmpty()) null else users - realm.username }
            }
        }

        fun list(hostname: String, cs: CredentialStore): Set<String> {
            val hostId = Realm(hostname = hostname, username = "").hash(cs)

            cs.createSocket().use { socket ->
                socket.getOutputStream().write(byteArrayOf(Command.READ.code) + hostId)
                try {
                    cs.auth(socket, hostId)
                } catch (e: ServerFailureException) {
                    return emptySet()
                }
                return receiveUsernameList(socket, cs.getSealKey())
            }
        }
    }
}

private fun updateUserList(socket: Socket, cs: Protocol.CredentialStore, realm: Protocol.Realm,
                           update: (Set<String>) -> Set<String>?) {
    val sos = socket.getOutputStream()
    val hostId = realm.withoutUser.hash(cs)

    sos.write(hostId)

    val sealKey = cs.getSealKey()
    val hostSk = cs.getSignKey(hostId)

    val usernameList = receiveUsernameList(socket, sealKey)
    val users = update(usernameList) ?: return

    val encrypted = sealKey.encrypt(users.joinToString("\u0000").toByteArray())
    val payloadSize = encrypted.size
    val envelope = if (usernameList.isEmpty()) {
        ByteBuffer.allocate(CRYPTO_SIGN_PUBLICKEYBYTES + 2 + payloadSize).put(hostSk.publicKey)
    } else {
        ByteBuffer.allocate(2 + payloadSize)
    }.order(ByteOrder.BIG_ENDIAN)
    envelope.putShort(payloadSize.toShort())
    envelope.put(encrypted)
    val message = envelope.array()
    sos.write(message + hostSk.sign(message))
}

fun Sphinx.Challenge.finish(salt: ByteArray, stream: InputStream): ByteArray =
    finish(salt, stream.readExactly(DECAF_255_SER_BYTES)) ?: throw Protocol.ServerFailureException()

fun sendRule(socket: Socket, charClasses: Set<CharacterClass>, size: Int, sealKey: SecretBoxKey, signKey: Ed25519PrivateKey) {
    val rule = (CharacterClass.serialize(charClasses).toInt() shl RULE_SHIFT) or (size and SIZE_MASK)
    val ruleBytes = ByteBuffer.allocate(RULE_BYTES_LENGTH).order(ByteOrder.BIG_ENDIAN).putShort(rule.toShort()).array()
    val ruleCipherText = sealKey.encrypt(ruleBytes)
    val msg = signKey.publicKey + ruleCipherText
    socket.getOutputStream().write(msg + signKey.sign(msg))
}

private fun receiveUsernameList(socket: Socket, key: SecretBoxKey): Set<String> {
    val source = socket.getInputStream()
    val length = source.readBE16()
    if (length == 0) return emptySet()
    val blob = source.readExactly(length)
    if (blob.equalsString("fail")) throw Protocol.ServerFailureException()
    return String(key.decrypt(blob)).split('\u0000').toSortedSet()
}

@Suppress("UsePropertyAccessSyntax")
private fun InputStream.readBE16(): Int {
    val len = ByteArray(4) // avoid overflows, as JVM short is signed
    read(len, 2, 2)
    return ByteBuffer.wrap(len).order(ByteOrder.BIG_ENDIAN).getInt()
}

private fun InputStream.readExactly(length: Int): ByteArray {
    val buffer = ByteArray(length)
    if (read(buffer) != length) throw Protocol.ServerFailureException()
    return buffer
}

fun Protocol.CredentialStore.getSignKey(id: ByteArray, rwd: ByteArray = ByteArray(0)): Ed25519PrivateKey =
    Ed25519PrivateKey.fromSeed(key.foldHash(Context.SIGNING, id, rwd))

fun Protocol.CredentialStore.getSealKey(rwd: ByteArray = ByteArray(0)): SecretBoxKey =
    SecretBoxKey.fromByteArray(key.foldHash(Context.ENCRYPTION, rwd))

fun Protocol.CredentialStore.auth(socket: Socket, hostId: ByteArray, rwd: ByteArray = ByteArray(0)) {
    val nonce = socket.getInputStream().readExactly(AUTH_NONCE_BYTES)
    socket.getOutputStream().write(getSignKey(hostId, rwd).sign(nonce))
}

private fun Protocol.CredentialStore.createSocket(): Socket = SSLSocketFactory.getDefault().createSocket(host, port)

private fun ByteArray.equalsString(other: String): Boolean = contentEquals(other.toByteArray())
