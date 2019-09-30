package org.hsbp.androsphinx

import android.util.Base64
import java.math.BigInteger

@Suppress("SpellCheckingInspection")
const val MOCK_KEY = "uj+gOoYGyyidDY58ISFaE7tCnj0+lxEGCyswnQLGALvtrdK8WGOkxlhHVicsNg7UKYfjO82p8KCRiYIAs75vBQ=="

@Suppress("SpellCheckingInspection")
const val SERVER_PK = "OWjZhVy23P7wRpTfZnmnd035BUYx5TdbivGGwD2ItCA="

class MockCredentialStore : Protocol.CredentialStore {
    private val users = mutableMapOf<BigInteger, MutableSet<String>>()

    override val host: String
        get() = "192.168.1.198"

    override val port: Int
        get() = 2355

    override val key: ByteArray
        get() = Base64.decode(MOCK_KEY, Base64.DEFAULT)

    override val salt: ByteArray
        get() = key.sliceArray(0 until SALT_BYTES)

    override val serverPublicKey: ByteArray
        get() = Base64.decode(SERVER_PK, Base64.DEFAULT)

    override fun cacheUser(hostId: ByteArray, username: String) {
        users.getOrPut(BigInteger(hostId), ::mutableSetOf).add(username)
    }

    override fun deleteUser(hostId: ByteArray, username: String) {
        users[BigInteger(hostId)]?.remove(username)
    }

    override fun getUsers(hostId: ByteArray): List<String> =
        users[BigInteger(hostId)]?.toList() ?: emptyList()
}