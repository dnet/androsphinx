package org.hsbp.androsphinx

import org.libsodium.jni.SodiumConstants
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
const val ENCRYPTED_RULE_LENGTH: Int = SodiumConstants.XSALSA20_POLY1305_SECRETBOX_NONCEBYTES + SodiumConstants.MAC_BYTES + RULE_BYTES_LENGTH

class Protocol {
    enum class Command(val code: Byte) {
        CREATE(0x00), READ(0x33), UNDO(0x55), GET(0x66), COMMIT(0x99.toByte()),
        CHANGE(0xAA.toByte()), WRITE(0xCC.toByte()), DELETE(0xFF.toByte());

        fun execute(realm: Realm, password: CharArray, cs: CredentialStore, callback: PasswordCallback, vararg extra: ByteArray) {
            Sphinx.Challenge(password).use { challenge ->
                val parts = sequence {
                    yield(realm.hash(cs))
                    yield(challenge.challenge)
                    yieldAll(extra.asSequence())
                }.toList()
                val message = ByteBuffer.allocate(parts.map { it.size }.sum() + 1)

                message.put(code)
                parts.forEach { message.put(it) }

                doSphinx(message.array(), challenge, cs, callback)
            }
        }

        fun execute(realm: Realm, cs: CredentialStore, callback: OneWayCallback) {
            val message = byteArrayOf(code) + realm.hash(cs)
            doSphinx(message, cs, callback)
        }
    }

    class Realm(val username: String, val hostname: String) {
        fun hash(cs: CredentialStore) = cs.hashId("$username|$hostname")

        val withoutUser: Realm
            get() = Realm(username = "", hostname = hostname)
    }

    class ServerFailureException : RuntimeException()

    interface CredentialStore {
        val key: MasterKey
        val host: String
        val port: Int
        val useTls: Boolean
        fun getUsers(hostId: ByteArray): List<String>
        fun cacheUser(hostId: ByteArray, username: String)
        fun deleteUser(hostId: ByteArray, username: String)
    }

    interface PasswordCallback {
        fun passwordReceived(password: CharArray)
    }

    interface OneWayCallback {
        fun commandCompleted()
    }

    companion object {

        fun create(password: CharArray, realm: Realm, charClasses: Set<CharacterClass>,
                   cs: CredentialStore, callback: PasswordCallback, size: Int = 0) {
            require(charClasses.isNotEmpty()) { "At least one character class must be allowed." }

            val rwd = cs.createSocket().use { socket ->
                val sis = socket.getInputStream()
                val sos = socket.getOutputStream()
                val id = realm.hash(cs)
                val rwd = Sphinx.Challenge(password).use { challenge ->
                    sos.write(byteArrayOf(Command.CREATE.code) + id + challenge.challenge)
                    val response = ByteArray(32)
                    sis.read(response)
                    challenge.finish(response)
                }
                sendRule(socket, charClasses, size, cs.getSealKey(rwd), cs.getSignKey(id, rwd))
                updateUserList(socket, cs, realm)

                rwd
            }

            callback.passwordReceived(CharacterClass.derive(Context.PASSWORD.foldHash(rwd), charClasses, size))
        }

        private fun updateUserList(socket: Socket, cs: CredentialStore, realm: Realm) {
            val sos = socket.getOutputStream()
            val hostId = realm.withoutUser.hash(cs)

            sos.write(hostId)

            val sealKey = cs.getSealKey()
            val hostSk = cs.getSignKey(hostId)

            val usernameList = receiveUsernameList(socket, sealKey)
            val prefix = if (usernameList.isEmpty()) hostSk.publicKey.asBytes else ByteArray(0)
            val users = usernameList + realm.username

            val (nonce, encrypted) = sealKey.encrypt(users.joinToString("\u0000").toByteArray())
            val lengthBytes = ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN).putShort(
                (nonce.size + encrypted.size).toShort()
            ).array()
            val message = prefix + lengthBytes + nonce + encrypted
            sos.write(message + hostSk.sign(message))
        }

        fun get(password: CharArray, realm: Realm, cs: CredentialStore, callback: PasswordCallback) {
            Command.GET.execute(realm, password, cs, callback)
        }

        fun change(password: CharArray, realm: Realm, cs: CredentialStore, callback: PasswordCallback) {
            Command.CHANGE.execute(realm, password, cs, callback)
        }

        fun commit(realm: Realm, cs: CredentialStore, callback: OneWayCallback) {
            Command.COMMIT.execute(realm, cs, callback)
        }

        fun delete(realm: Realm, cs: CredentialStore) {
            val callback = object : OneWayCallback {
                override fun commandCompleted() {
                    cs.deleteUser(cs.hashId(realm.hostname), realm.username)
                }
            }
            Command.DELETE.execute(realm, cs, callback)
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

fun sendRule(socket: Socket, charClasses: Set<CharacterClass>, size: Int, sealKey: SecretBoxKey, signKey: Ed25519PrivateKey) {
    val rule = (CharacterClass.serialize(charClasses).toInt() shl RULE_SHIFT) or (size and SIZE_MASK)
    val ruleBytes = ByteBuffer.allocate(RULE_BYTES_LENGTH).order(ByteOrder.BIG_ENDIAN).putShort(rule.toShort()).array()
    val (ruleNonce, ruleCipherText) = sealKey.encrypt(ruleBytes)
    val msg = signKey.publicKey.asBytes + ruleNonce + ruleCipherText
    socket.getOutputStream().write(msg + signKey.sign(msg))
}

private fun receiveUsernameList(socket: Socket, key: SecretBoxKey): Set<String> {
    val source = socket.getInputStream()
    val length = source.readBE16()
    if (length == 0) return emptySet()
    val blob = ByteArray(length)
    source.read(blob)
    if (blob.equalsString("fail")) throw Protocol.ServerFailureException()
    return String(key.decrypt(blob)).split('\u0000').toSortedSet()
}

@Suppress("UsePropertyAccessSyntax")
private fun InputStream.readBE16(): Int {
    val len = ByteArray(4) // avoid overflows, as JVM short is signed
    read(len, 2, 2)
    return ByteBuffer.wrap(len).order(ByteOrder.BIG_ENDIAN).getInt()
}

fun Protocol.CredentialStore.hashId(hostname: String): ByteArray = key.foldHash(Context.SALT, hostname.toByteArray())

fun Protocol.CredentialStore.getSignKey(id: ByteArray, rwd: ByteArray = ByteArray(0)): Ed25519PrivateKey =
    Ed25519PrivateKey.fromSeed(key.foldHash(Context.SIGNING, id, rwd))

fun Protocol.CredentialStore.getSealKey(rwd: ByteArray = ByteArray(0)): SecretBoxKey =
    SecretBoxKey.fromByteArray(key.foldHash(Context.ENCRYPTION, rwd))

fun Protocol.CredentialStore.auth(socket: Socket, hostId: ByteArray, challenge: Sphinx.Challenge? = null) {
    val sis = socket.getInputStream()
    val sos = socket.getOutputStream()
    val nonce = ByteArray(AUTH_NONCE_BYTES)
    val rwd = if (challenge == null) {
        if (sis.read(nonce) != nonce.size) throw Protocol.ServerFailureException()
        ByteArray(0)
    } else {
        val beta = ByteArray(DECAF_255_SER_BYTES)
        if (sis.read(beta) != beta.size) throw Protocol.ServerFailureException()
        if (sis.read(nonce) != nonce.size) throw Protocol.ServerFailureException()
        challenge.finish(beta)
    }
    sos.write(getSignKey(hostId, rwd).sign(nonce))
}

@Suppress("UsePropertyAccessSyntax")
private fun doSphinx(message: ByteArray, challenge: Sphinx.Challenge,
                     cs: Protocol.CredentialStore, callback: Protocol.PasswordCallback) {
    val payload = communicateWithServer(message, cs)
    if (payload.sliceArray(0 until payload.size - ENCRYPTED_RULE_LENGTH).equalsString("fail")
                || payload.size != DECAF_255_SER_BYTES + ENCRYPTED_RULE_LENGTH) {
        throw Protocol.ServerFailureException()
    }
    val rwd = challenge.finish(payload)

    val encryptedRule = payload.sliceArray(DECAF_255_SER_BYTES until payload.size)
    val ruleBytes = cs.getSealKey(rwd).decrypt(encryptedRule)
    val combined = ByteBuffer.wrap(ruleBytes).order(ByteOrder.BIG_ENDIAN).getShort().toInt()
    val size = combined and SIZE_MASK
    val rule = CharacterClass.parse((combined shr RULE_SHIFT).toByte())
    callback.passwordReceived(CharacterClass.derive(Context.PASSWORD.foldHash(rwd), rule, size))
}

private fun doSphinx(message: ByteArray,
                     cs: Protocol.CredentialStore, callback: Protocol.OneWayCallback) {
    val payload = communicateWithServer(message, cs)
    if (payload.equalsString("ok")) {
        callback.commandCompleted()
    } else {
        throw Protocol.ServerFailureException()
    }
}

private fun communicateWithServer(message: ByteArray, cs: Protocol.CredentialStore): ByteArray {
    return cs.createSocket().use { s ->
        s.getOutputStream().write(message)
        val result = ByteArray(DECAF_255_SER_BYTES + ENCRYPTED_RULE_LENGTH)
        s.getInputStream().read(result)
        result
    }
}

fun Protocol.CredentialStore.createSocket(): Socket =
    if (useTls) SSLSocketFactory.getDefault().createSocket(host, port) else Socket(host, port)

private fun ByteArray.equalsString(other: String): Boolean = contentEquals(other.toByteArray())