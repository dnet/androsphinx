package org.hsbp.androsphinx

import android.util.Base64
import java.math.BigInteger

@Suppress("SpellCheckingInspection")
const val MOCK_KEY = "qshl2mv7A76V2io93b2oS9cjNTTupuWFf7z10aJP5LM="

class MockCredentialStore : Protocol.CredentialStore {
    private val users = mutableMapOf<BigInteger, MutableSet<String>>()

    override val host: String
        get() = "10.0.2.2"

    override val port: Int
        get() = 2355

    override val useTls: Boolean
        get() = true

    override val key: MasterKey
        get() = MasterKey.fromByteArray(Base64.decode(MOCK_KEY, Base64.DEFAULT))
}