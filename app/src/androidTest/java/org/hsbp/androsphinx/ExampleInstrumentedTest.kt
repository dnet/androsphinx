package org.hsbp.androsphinx

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry

import org.junit.Test
import org.junit.runner.RunWith

import org.junit.Assert.*
import org.libsodium.jni.NaCl
import org.libsodium.jni.Sodium

/**
 * Instrumented test, which will execute on an Android device.
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */

@Suppress("SpellCheckingInspection")
const val EXPECTED_BASIC_TEST = "Dnw7PR+5GmrE/t6RtaF12gPIQSWaIGaSje7RgQvasy4="

@RunWith(AndroidJUnit4::class)
class ExampleInstrumentedTest {
    @Test
    fun sphinxBasicTest() {
        val c = Sphinx.Challenge("shitty password\u0000".toCharArray())
        val secret = ByteArray(32) { ' '.toByte() }
        val resp = Sphinx.respond(c.challenge, secret)
        val rwd = c.finish(resp)
        assertArrayEquals(rwd, Base64.decode(EXPECTED_BASIC_TEST, Base64.DEFAULT))
    }

    @Test
    fun storageTest() {
        NaCl.sodium()
        val appContext = InstrumentationRegistry.getInstrumentation().targetContext
        val storage = AndroidCredentialStore(appContext)
        val key = storage.key
        assertEquals(key.size, Sodium.crypto_sign_secretkeybytes())
        assertArrayEquals(key, storage.key)
        assertEquals(storage.salt.size, SALT_BYTES)

        val host1 = ByteArray(16) { 1 }
        val host2 = ByteArray(16) { 2 }
        val host1user1 = "foo"
        val host1user2 = "bar"
        val host2user1 = "baz"

        assert(storage.getUsers(host1).isEmpty())
        storage.deleteUser(host1, host1user1)

        storage.cacheUser(host1, host1user1)
        assertEquals(storage.getUsers(host1).size, 1)
        assert(storage.getUsers(host1).contains(host1user1))

        storage.cacheUser(host1, host1user2)
        assertEquals(storage.getUsers(host1).size, 2)
        assert(storage.getUsers(host1).containsAll(listOf(host1user1, host1user2)))

        storage.cacheUser(host2, host2user1)
        assertEquals(storage.getUsers(host1).size, 2)
        assert(storage.getUsers(host1).containsAll(listOf(host1user1, host1user2)))
        assertEquals(storage.getUsers(host2).size, 1)
        assert(storage.getUsers(host1).contains(host1user2))

        storage.deleteUser(host1, host1user1)
        assertEquals(storage.getUsers(host1).size, 1)
        assert(storage.getUsers(host1).contains(host1user2))

        assertEquals(storage.host, "")
        assertEquals(storage.port, 0)
        assert(storage.serverPublicKey.isEmpty())

        val host = "example.tld"
        val port = 31337
        val serverPublicKey = ByteArray(32) { 3 }
        appContext.storeServerInfo(host, port, serverPublicKey)

        assertEquals(storage.host, host)
        assertEquals(storage.port, port)
        assertArrayEquals(storage.serverPublicKey, serverPublicKey)
    }
}
