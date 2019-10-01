package org.hsbp.androsphinx

import java.lang.IllegalStateException
import java.lang.RuntimeException
import java.net.Socket

const val SIZE_MASK: Int = 0x7F
const val RULE_SHIFT: Int = 7

class Protocol {
    enum class Command(private val code: Byte) {
        CREATE(0x00), GET(0x66), COMMIT(0x99.toByte()), CHANGE(0xAA.toByte()), DELETE(0xFF.toByte());

        @ExperimentalUnsignedTypes
        fun execute(realm: Realm, challenge: Sphinx.Challenge?, cs: CredentialStore, callback: Callback, vararg extra: ByteArray) {
            val parts = sequence {
                yield(realm.hash(cs))
                if (challenge != null) yield(challenge.challenge)
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

    class Realm(val username: String, val hostname: String) {
        fun hash(cs: CredentialStore) = cs.hashId(username + hostname)
    }

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

    interface Callback {
        fun passwordReceived(password: CharArray)
        fun commandCompleted()
    }

    companion object {
        @ExperimentalUnsignedTypes
        fun create(password: CharArray, realm: Realm, charClasses: Set<CharacterClass>,
                   cs: CredentialStore, callback: Callback, size: Int = 0) {
            val rule = (CharacterClass.serialize(charClasses).toInt() shl RULE_SHIFT) or (size and SIZE_MASK)
            val ruleBytes = byteArrayOf(((rule and 0xFF00) shr 8).toByte(), (rule and 0xFF).toByte())
            val encryptedRule = secretBox(ruleBytes, cs.ruleKey)
            val challenge = Sphinx.Challenge(password)
            Command.CREATE.execute(realm, challenge, cs, callback, encryptedRule, skToPk(cs.key))
        }

        @ExperimentalUnsignedTypes
        fun get(password: CharArray, realm: Realm, cs: CredentialStore, callback: Callback) {
            Command.GET.execute(realm, Sphinx.Challenge(password), cs, callback)
        }

        @ExperimentalUnsignedTypes
        fun change(password: CharArray, realm: Realm, cs: CredentialStore, callback: Callback) {
            Command.CHANGE.execute(realm, Sphinx.Challenge(password), cs, callback)
        }

        @ExperimentalUnsignedTypes
        fun commit(realm: Realm, cs: CredentialStore, callback: Callback) {
            Command.COMMIT.execute(realm, null, cs, callback)
        }

        @ExperimentalUnsignedTypes
        fun delete(realm: Realm, cs: CredentialStore) {
            val callback = object : Callback {
                override fun commandCompleted() {
                    cs.deleteUser(cs.hashId(realm.hostname), realm.username)
                }

                override fun passwordReceived(password: CharArray) {
                    throw IllegalStateException()
                }
            }
            Command.DELETE.execute(realm, null, cs, callback)
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

@ExperimentalUnsignedTypes
private fun doSphinx(message: ByteArray, realm: Protocol.Realm, challenge: Sphinx.Challenge?,
                     cs: Protocol.CredentialStore, callback: Protocol.Callback) {
    val payload = communicateWithServer(message, cs)
    if (challenge == null) {
        callback.commandCompleted()
        return
    }
    val rwd = challenge.finish(payload.sliceArray(0 until DECAF_255_SER_BYTES))

    if (realm.username !in Protocol.list(realm.hostname, cs)) {
        cs.cacheUser(cs.hashId(realm.hostname), realm.username)
    }

    val encryptedRule = payload.sliceArray(DECAF_255_SER_BYTES until payload.size)
    val ruleBytes = secretBoxOpen(encryptedRule.sliceArray(24 until encryptedRule.size),
        encryptedRule.sliceArray(0 until 24), cs.ruleKey)
    val combined = (ruleBytes[0].toInt() shl 8) or ruleBytes[1].toInt()
    val size = combined and SIZE_MASK
    val rule = CharacterClass.parse((combined shr RULE_SHIFT).toByte())
    callback.passwordReceived(CharacterClass.derive(rwd, rule, size))
}

private fun communicateWithServer(message: ByteArray, cs: Protocol.CredentialStore): ByteArray {
    val signed = cryptoSign(message, cs.key)
    val data = Socket(cs.host, cs.port).use { s ->
        s.getOutputStream().write(signed)
        s.getInputStream().readBytes()
    }
    val payload = cryptoSignOpen(data, cs.serverPublicKey)
    if (!payload.contentEquals("ok".toByteArray()) &&
        (payload.sliceArray(0 until payload.size - ENCRYPTED_RULE_LENGTH).contentEquals("fail".toByteArray())
                || payload.size != DECAF_255_SER_BYTES + ENCRYPTED_RULE_LENGTH)
    ) {
        throw RuntimeException("Server failure")
    }
    return payload
}