package org.hsbp.androsphinx

import java.lang.IllegalStateException
import java.net.Socket

class Protocol {
    enum class Command(private val code: Byte) {
        CREATE(0x00), GET(0x66), COMMIT(0x99.toByte()), CHANGE(0xAA.toByte()), DELETE(0xFF.toByte());

        fun execute(username: String, hostname: String, challenge: Sphinx.Challenge?, cs: CredentialStore, callback: Callback?, vararg extra: ByteArray) {
            val parts = sequence {
                yield(cs.hashId(username + hostname))
                if (challenge != null) yield(challenge.challenge)
                yieldAll(extra.asSequence())
            }.toList()
            val message = ByteArray(parts.map(ByteArray::size).sum() + 1)

            message[0] = code
            parts.fold(1) { offset, part ->
                val ps = part.size
                System.arraycopy(part, 0, message, offset, ps)
                offset + ps
            }

            doSphinx(message, hostname, challenge, cs, callback)
        }
    }

    interface CredentialStore {
        val key: ByteArray
        val salt: ByteArray
        val host: String
        val port: Int
        fun getUsers(hostId: ByteArray): List<String>
        fun cacheUser(hostId: ByteArray, username: String)
        fun deleteUser(hostId: ByteArray, username: String)
    }

    interface Callback {
        fun passwordReceived(password: CharArray)
        fun commandCompleted()
    }

    companion object {
        fun create(password: CharArray, username: String, hostname: String,
                   charClasses: Set<CharacterClass>, cs: CredentialStore, callback: Callback?, size: Int = 0) {
            val rule = (CharacterClass.serialize(charClasses).toInt() shl 7) or (size and 0x7f)
            val ruleBytes = byteArrayOf(((rule and 0xFF00) shr 8).toByte(), (rule and 0xFF).toByte())
            val sk = cs.key
            val rk = genericHash(sk, cs.salt)
            val encryptedRule = secretBox(ruleBytes, rk)
            val challenge = Sphinx.Challenge(password)
            Command.CREATE.execute(username, hostname, challenge, cs, callback, encryptedRule, skToPk(sk))
        }

        fun get(password: CharArray, username: String, hostname: String, cs: CredentialStore, callback: Callback?) {
            Command.GET.execute(username, hostname, Sphinx.Challenge(password), cs, callback)
        }

        fun change(password: CharArray, username: String, hostname: String, cs: CredentialStore, callback: Callback?) {
            Command.CHANGE.execute(username, hostname, Sphinx.Challenge(password), cs, callback)
        }

        fun commit(username: String, hostname: String, cs: CredentialStore, callback: Callback?) {
            Command.COMMIT.execute(username, hostname, null, cs, callback)
        }

        fun delete(username: String, hostname: String, cs: CredentialStore) {
            val callback = object : Callback {
                override fun commandCompleted() {
                    cs.deleteUser(cs.hashId(hostname), username)
                }

                override fun passwordReceived(password: CharArray) {
                    throw IllegalStateException()
                }
            }
            Command.DELETE.execute(username, hostname, null, cs, callback)
        }

        fun list(hostname: String, cs: CredentialStore): List<String> =
            cs.getUsers(cs.hashId(hostname))
    }
}

fun Protocol.CredentialStore.hashId(hostname: String): ByteArray {
    return genericHash(hostname.toByteArray(), salt)
}

private fun doSphinx(message: ByteArray, hostname: String, challenge: Sphinx.Challenge?,
                     cs: Protocol.CredentialStore, callback: Protocol.Callback?) {
    val hostId = cs.hashId(hostname)
    val signed = cryptoSign(message, cs.key)
    val data = Socket(cs.host, cs.port).use { s ->
        s.getOutputStream().write(message)
        s.getInputStream().readBytes()
    }
    TODO("parse 'data'")
}