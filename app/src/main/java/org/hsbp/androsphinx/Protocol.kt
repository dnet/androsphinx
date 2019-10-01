package org.hsbp.androsphinx

import java.lang.RuntimeException
import java.net.Socket

const val SIZE_MASK: Int = 0x7F
const val RULE_SHIFT: Int = 7

class Protocol {
    enum class Command(private val code: Byte) {
        CREATE(0x00), GET(0x66), COMMIT(0x99.toByte()), CHANGE(0xAA.toByte()), DELETE(0xFF.toByte());

        fun execute(realm: Realm, password: CharArray, cs: CredentialStore, callback: PasswordCallback, vararg extra: ByteArray) {
            Sphinx.Challenge(password).use { challenge ->
                val parts = sequence {
                    yield(realm.hash(cs))
                    yield(challenge.challenge)
                    yieldAll(extra.asSequence())
                }.toList()
                val message = ByteArray(parts.map { it.size }.sum() + 1)

                message[0] = code
                parts.fold(1) { offset, part ->
                    val ps = part.size
                    System.arraycopy(part, 0, message, offset, ps)
                    offset + ps
                }

                doSphinx(message, realm, challenge, cs, callback)
            }
        }

        fun execute(realm: Realm, cs: CredentialStore, callback: OneWayCallback) {
            val message = byteArrayOf(code) + realm.hash(cs)
            doSphinx(message, cs, callback)
        }
    }

    class Realm(val username: String, val hostname: String) {
        fun hash(cs: CredentialStore) = cs.hashId(username + hostname)
    }

    class ServerFailureException : RuntimeException()

    interface CredentialStore {
        val key: ByteArray
        val salt: ByteArray
        val host: String
        val port: Int
        val serverPublicKey: ByteArray
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
            val rule = (CharacterClass.serialize(charClasses).toInt() shl RULE_SHIFT) or (size and SIZE_MASK)
            val ruleBytes = byteArrayOf(((rule and 0xFF00) shr 8).toByte(), (rule and 0xFF).toByte())
            val (ruleNonce, ruleCipherText) = secretBox(ruleBytes, cs.ruleKey)
            Command.CREATE.execute(realm, password, cs, callback, ruleNonce, ruleCipherText, skToPk(cs.key))
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

        fun list(hostname: String, cs: CredentialStore): List<String> =
            cs.getUsers(cs.hashId(hostname))
    }
}

fun Protocol.CredentialStore.hashId(hostname: String): ByteArray {
    return genericHash(hostname.toByteArray(), salt)
}

val Protocol.CredentialStore.ruleKey
    get() = genericHash(key, salt)

const val ENCRYPTED_RULE_LENGTH: Int = 42

private fun doSphinx(message: ByteArray, realm: Protocol.Realm, challenge: Sphinx.Challenge,
                     cs: Protocol.CredentialStore, callback: Protocol.PasswordCallback) {
    val payload = communicateWithServer(message, cs)
    if (payload.sliceArray(0 until payload.size - ENCRYPTED_RULE_LENGTH).equalsString("fail")
                || payload.size != DECAF_255_SER_BYTES + ENCRYPTED_RULE_LENGTH) {
        throw Protocol.ServerFailureException()
    }
    val rwd = challenge.finish(payload.sliceArray(0 until DECAF_255_SER_BYTES))

    if (realm.username !in Protocol.list(realm.hostname, cs)) {
        cs.cacheUser(cs.hashId(realm.hostname), realm.username)
    }

    val encryptedRule = payload.sliceArray(DECAF_255_SER_BYTES until payload.size)
    val ruleBytes = secretBoxOpen(encryptedRule, cs.ruleKey)
    val combined = (ruleBytes[0].toInt() shl 8) or ruleBytes[1].toInt()
    val size = combined and SIZE_MASK
    val rule = CharacterClass.parse((combined shr RULE_SHIFT).toByte())
    callback.passwordReceived(CharacterClass.derive(rwd, rule, size))
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
    val signed = cryptoSign(message, cs.key)
    val data = Socket(cs.host, cs.port).use { s ->
        s.getOutputStream().write(signed)
        s.getInputStream().readBytes()
    }
    return cryptoSignOpen(data, cs.serverPublicKey)
}

private fun ByteArray.equalsString(other: String): Boolean = contentEquals(other.toByteArray())