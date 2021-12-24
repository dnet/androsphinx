// SPDX-FileCopyrightText: 2019, Andras Veres-Szentkiralyi <vsza@vsza.hu>
// SPDX-License-Identifier: MIT

package org.hsbp.androsphinx

import org.hsbp.equihash.Equihash
import java.io.InputStream
import java.lang.RuntimeException
import java.math.BigInteger
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.net.ssl.SSLSocketFactory

const val RULE_BYTES_LENGTH: Int = 38
const val AUTH_NONCE_BYTES: Int = 32
const val CHALLENGE_CREATE: Byte = 0x5a
const val CHALLENGE_VERIFY: Byte = 0xa5.toByte()
const val VERSION_LENGTH: Int = 1
const val ENCRYPTED_RULE_LENGTH: Int = CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES + RULE_BYTES_LENGTH + VERSION_LENGTH

class Protocol {
    enum class Command(val code: Byte, val requiresAuth: Boolean = true,
                       val writeRule: Boolean = false, val rateLimit: Boolean = true) {
        CREATE(0x00, requiresAuth = false, writeRule = true, rateLimit = false),
        READ(0x33), UNDO(0x55, writeRule = true),
        GET(0x66, requiresAuth = false), COMMIT(0x99.toByte(), writeRule = true),
        CHANGE(0xAA.toByte()), WRITE(0xCC.toByte()), DELETE(0xFF.toByte());

        fun <T> connect(cs: CredentialStore, password: CharArray, id: ByteArray, body: (Socket, Sphinx.Challenge, ByteArray) -> T): T {
            Sphinx.Challenge(password).use { challenge ->
                val message = ByteBuffer.allocate(DECAF_255_SER_BYTES + CRYPTO_GENERICHASH_BYTES + 1)
                message.put(code)
                message.put(id)
                message.put(challenge.challenge)
                val request = message.array()
                val s = if (rateLimit) {
                    performRateLimit(cs, request)
                } else {
                    cs.createSocket().apply { getOutputStream().write(request) }
                }
                s.use { socket ->
                    val rwd = challenge.finish(id, socket.getInputStream())
                    if (requiresAuth) cs.auth(socket, id, rwd)
                    return body(socket, challenge, rwd)
                }
            }
        }

        private fun performRateLimit(cs: CredentialStore, request: ByteArray): Socket {
            val challenge = cs.createSocket().use { s ->
                s.getOutputStream().write(byteArrayOf(CHALLENGE_CREATE) + request)
                s.getInputStream().readExactly(1 + 1 + 8 + 32)
            }
            val n = challenge[0]
            val k = challenge[1]
            val seed = challenge + request
            val solution = Equihash.solve(n.toInt(), k.toInt(), seed)!!
            val socket = cs.createSocket()
            socket.getOutputStream().apply {
                write(byteArrayOf(CHALLENGE_VERIFY) + challenge)
                write(request)
                write(solution)
            }
            return socket
        }

        @Suppress("UsePropertyAccessSyntax")
        fun execute(realm: Realm, password: CharArray, cs: CredentialStore, callback: PasswordCallback,
                    createRule: Rule? = null) {
            val hostId = realm.hash(cs)

            val derived = connect(cs, password, hostId) { s, challenge, oldRwd ->
                val sis = s.getInputStream()
                val newRwd = if (requiresAuth) challenge.finish(hostId, sis) else oldRwd

                val rule = if (createRule == null) {
                    val (version, ruleBytes) = cs.getSealKey().decrypt(sis.readExactly(ENCRYPTED_RULE_LENGTH))
                    Rule.parse(ruleBytes)
                } else createRule.withCheckDigit(calculateCheckDigit(oldRwd))

                if (writeRule) {
                    sendRule(s, rule, cs.getSealKey(), cs.getSignKey(hostId, newRwd))
                }

                if (createRule != null) {
                    updateUserList(s, cs, realm) { users -> users + realm.username }
                }

                val rwd = BigInteger(POSITIVE, Context.PASSWORD.foldHash(newRwd)).xor(rule.xorMask)
                CharacterClass.derive(rwd, rule.charClasses, rule.size.toInt(), rule.symbols)
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
        val rwdKeys: Boolean
    }

    interface PasswordCallback {
        fun passwordReceived(password: CharArray)
    }

    companion object {

        fun create(password: CharArray, realm: Realm, charClasses: Set<CharacterClass>,
                   cs: CredentialStore, callback: PasswordCallback, size: Int = 0) {
            require(charClasses.isNotEmpty()) { "At least one character class must be allowed." }
            val symbols = if (charClasses.contains(CharacterClass.SYMBOLS)) SYMBOL_SET.toSet() else emptySet() // TODO allow fine-grain control
            val xorMask = BigInteger.ZERO // TODO add support for non-zero xorMask creation
            val rule = Rule(charClasses, symbols, size.toBigInteger(), xorMask)
            Command.CREATE.execute(realm, password, cs, callback, rule)
        }

        fun calculateCheckDigit(rwd: ByteArray): BigInteger {
            return BigInteger(POSITIVE, Context.CHECK_DIGIT.foldHash(rwd))
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

    val sealKey = cs.getSealKey()
    val hostSk = cs.getSignKey(hostId, ByteArray(0))

    sos.write(hostId + hostSk.sign(hostId))

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

fun sendRule(socket: Socket, rule: Rule, sealKey: AeadKey, signKey: Ed25519PrivateKey) {
    val ruleCipherText = sealKey.encrypt(rule.serialize())
    val msg = signKey.publicKey + ruleCipherText
    socket.getOutputStream().write(msg + signKey.sign(msg))
}

private fun receiveUsernameList(socket: Socket, key: AeadKey): Set<String> {
    val source = socket.getInputStream()
    val length = source.readBE16()
    if (length == 0) return emptySet()
    val blob = source.readExactly(length)
    if (blob.equalsString("fail")) throw Protocol.ServerFailureException()
    val (version, decrypted) = key.decrypt(blob)
    return String(decrypted).split('\u0000').toSortedSet()
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

fun Protocol.CredentialStore.getSignKey(id: ByteArray, rwd: ByteArray? = null): Ed25519PrivateKey =
    Ed25519PrivateKey.fromSeed(key.foldHash(Context.SIGNING, id, if (rwdKeys) rwd else null))

fun Protocol.CredentialStore.getSealKey(): AeadKey =
    AeadKey.fromByteArray(key.foldHash(Context.ENCRYPTION))

fun Protocol.CredentialStore.auth(socket: Socket, hostId: ByteArray, rwd: ByteArray? = null) {
    val nonce = socket.getInputStream().readExactly(AUTH_NONCE_BYTES)
    socket.getOutputStream().write(getSignKey(hostId, rwd).sign(nonce))
}

private fun Protocol.CredentialStore.createSocket(): Socket = SSLSocketFactory.getDefault().createSocket(host, port)

private fun ByteArray.equalsString(other: String): Boolean = contentEquals(other.toByteArray())
