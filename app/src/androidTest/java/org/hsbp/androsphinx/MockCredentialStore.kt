package org.hsbp.androsphinx

import android.util.Base64
import java.math.BigInteger

@Suppress("SpellCheckingInspection")
const val MOCK_KEY = "uj+gOoYGyyidDY58ISFaE7tCnj0+lxEGCyswnQLGALvtrdK8WGOkxlhHVicsNg7UKYfjO82p8KCRiYIAs75vBQ=="

@Suppress("SpellCheckingInspection")
const val SERVER_PK = "45eSphbgoJbzB9pG37NJj98cuR6grERC2newnBMDFZ8"

class MockCredentialStore : Protocol.CredentialStore {
    private val users = mutableMapOf<BigInteger, MutableSet<String>>()

    override val host: String
        get() = "10.0.2.2"

    override val port: Int
        get() = 2355

    override val key: Ed25519PrivateKey
        get() = Ed25519PrivateKey.fromByteArray(Base64.decode(MOCK_KEY, Base64.DEFAULT))

    override val salt: Salt
        get() = Salt.fromByteArray(Base64.decode(MOCK_KEY, Base64.DEFAULT).sliceArray(0 until SALT_BYTES))

    override val serverPublicKey: Ed25519PublicKey
        get() = Ed25519PublicKey.fromBase64(SERVER_PK)

    override fun cacheUser(hostId: ByteArray, username: String) {
        users.getOrPut(BigInteger(hostId), ::mutableSetOf).add(username)
    }

    override fun deleteUser(hostId: ByteArray, username: String) {
        users[BigInteger(hostId)]?.remove(username)
    }

    override fun getUsers(hostId: ByteArray): List<String> =
        users[BigInteger(hostId)]?.toList() ?: emptyList()
}