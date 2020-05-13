package org.hsbp.androsphinx

import android.util.Base64

@Suppress("SpellCheckingInspection")
const val MOCK_KEY = "qshl2mv7A76V2io93b2oS9cjNTTupuWFf7z10aJP5LM="

class MockCredentialStore : Protocol.CredentialStore {
    override val host: String
        get() = "sphinx-test.silentsignal.hu"

    override val port: Int
        get() = 2355

    override val useTls: Boolean
        get() = true

    override val key: MasterKey
        get() = MasterKey.fromByteArray(Base64.decode(MOCK_KEY, Base64.DEFAULT))
}