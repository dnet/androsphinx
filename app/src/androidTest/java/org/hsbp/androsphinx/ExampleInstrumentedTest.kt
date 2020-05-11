package org.hsbp.androsphinx

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry

import org.junit.Test
import org.junit.runner.RunWith

import org.junit.Assert.*
import org.libsodium.jni.NaCl
import org.libsodium.jni.Sodium
import java.io.PrintWriter
import java.lang.NumberFormatException
import java.net.ServerSocket
import java.nio.ByteBuffer
import java.util.*

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
        Sphinx.Challenge("shitty password\u0000".toCharArray()).use { c ->
            val secret = ByteArray(32) { ' '.toByte() }
            val resp = Sphinx.respond(c.challenge, secret)
            val rwd = c.finish(resp)
            assertArrayEquals(Base64.decode(EXPECTED_BASIC_TEST, Base64.DEFAULT), rwd)
        }
    }

    @Test
    fun storageTest() {
        NaCl.sodium()
        val appContext = InstrumentationRegistry.getInstrumentation().targetContext
        val storage = AndroidCredentialStore(appContext)
        val key = storage.key
        assertEquals(Sodium.crypto_sign_secretkeybytes(), key.asBytes.size)
        assertArrayEquals(storage.key.asBytes, key.asBytes)

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
        assertEquals(2, storage.getUsers(host1).size)
        assert(storage.getUsers(host1).containsAll(listOf(host1user1, host1user2)))
        assertEquals(1, storage.getUsers(host2).size)
        assert(storage.getUsers(host1).contains(host1user2))

        storage.deleteUser(host1, host1user1)
        assertEquals(1, storage.getUsers(host1).size)
        assert(storage.getUsers(host1).contains(host1user2))

        assertEquals("", storage.host)
        assertEquals(0, storage.port)

        val host = "example.tld"
        val port = 31337
        appContext.storeServerInfo(host, port)

        assertEquals(host, storage.host)
        assertEquals(port, storage.port)
    }

    @Test
    fun sodiumHelperTest() {
        NaCl.sodium()
        val serverSigningPrivateKey = Ed25519PrivateKey.generate()
        val serverSigningPublicKey = serverSigningPrivateKey.publicKey
        val input = "dataToBeSealed".toByteArray()
        val sealed = serverSigningPublicKey.asCurve25519PublicKey.seal(input)
        val output = serverSigningPrivateKey.asCurve25519PrivateKey.unseal(sealed)
        assertArrayEquals(input, output)
    }

    @Test
    fun sphinxNetworkTest() {
        NaCl.sodium()
        val cs = MockCredentialStore()
        val username = "network"
        val username2 = "network2"
        val hostname = "test${System.currentTimeMillis()}.tld"
        val realm = Protocol.Realm(username, hostname)
        val realm2 = Protocol.Realm(username2, hostname)
        val charClasses = setOf(CharacterClass.LOWER, CharacterClass.DIGITS)
        val size = 18
        val callback = object : Protocol.PasswordCallback {
            var gotPassword: CharArray? = null

            override fun passwordReceived(password: CharArray) {
                gotPassword = password
            }
        }

        assert(Protocol.list(hostname, cs).isEmpty())

        Protocol.create("sphinxNetworkTestMasterPassword".toCharArray(), realm, charClasses, cs, callback, size)
        assertNotNull(callback.gotPassword)
        val pw = callback.gotPassword!!
        assertEquals(size, pw.size)
        assert(pw.all { pwChar -> charClasses.any { it.range.contains(pwChar) } })
        val userList = Protocol.list(hostname, cs)
        assertEquals(1, userList.size)
        assert(userList.contains(username))

        Protocol.create("sphinxNetworkTestMasterPassword2".toCharArray(), realm2, charClasses, cs, callback, size)
        val userList2 = Protocol.list(hostname, cs)
        assertEquals(2, userList2.size)
        assert(userList2.contains(username))
        assert(userList2.contains(username2))

        callback.gotPassword = null

        Protocol.get("sphinxNetworkTestMasterPassword".toCharArray(), realm, cs, callback)
        assertArrayEquals(pw, callback.gotPassword)

        callback.gotPassword = null

        Protocol.change("sphinxNetworkTestMasterPassword".toCharArray(), realm, cs, callback)
        val pw2 = callback.gotPassword!!
        assertFalse(pw.contentEquals(pw2))

        callback.gotPassword = null

        Protocol.get("sphinxNetworkTestMasterPassword".toCharArray(), realm, cs, callback)
        assertArrayEquals(pw, callback.gotPassword)

        val oneWayCallback = object : Protocol.OneWayCallback {
            var called = false

            override fun commandCompleted() {
                called = true
            }
        }

        Protocol.commit(realm, cs, oneWayCallback)
        assert(oneWayCallback.called)

        callback.gotPassword = null

        Protocol.get("sphinxNetworkTestMasterPassword".toCharArray(), realm, cs, callback)
        assertArrayEquals(pw2, callback.gotPassword)

        Protocol.delete(realm, cs)
        assert(Protocol.list(hostname, cs).isEmpty())

        try {
            Protocol.get("sphinxNetworkTestMasterPassword".toCharArray(), realm, cs, callback)
            fail("ServerFailureException should've been thrown")
        } catch (e: Protocol.ServerFailureException) {
            // success
        }
    }

    @Test
    fun readEvalPrintLoopTest() {
        NaCl.sodium()
        ServerSocket(2355).accept().use { socket ->
            val br = socket.getInputStream().bufferedReader()
            val pw = PrintWriter(socket.getOutputStream().writer())
            val cs = MockCredentialStore()

            while (true) {
                pw.write("ASREPL> ")
                pw.flush()
                val cmd = br.readLine() ?: break
                processCommand(cmd, pw, cs)
            }
        }
    }
}

private fun processCommand(cmd: String, pw: PrintWriter, cs: Protocol.CredentialStore) {
    if (cmd == "help") {
        pw.println("Available commands:")
        pw.println()
        pw.println("create <master password> <user> <site> [u][l][d][s] [<size>]")
        pw.println("<get|change> <master password> <user> <site>")
        pw.println("<commit|delete> <user> <site>")
        pw.println("list <site>")
        return
    }

    val parts = cmd.split(' ')
    if (parts.size < 2) {
        pw.println("Not enough arguments or unknown command")
        return
    }

    val passwordCallback = object : Protocol.PasswordCallback {
        override fun passwordReceived(password: CharArray) {
            pw.println(String(password))
        }
    }

    val oneWayCallback = object : Protocol.OneWayCallback {
        override fun commandCompleted() {
            pw.println("committed")
        }
    }

    try {
        when (parts[0]) {
            "create" -> {
                if (parts.size < 5) {
                    pw.println("Not enough arguments")
                }
                try {
                    val size = if (parts.size > 5) parts[5].toInt() else 0
                    val ccs = parts[4].toLowerCase()
                    val cc = CharacterClass.values().filterTo(
                        EnumSet.noneOf(
                            CharacterClass::class.java
                        )
                    ) { it.name[0].toLowerCase() in ccs }
                    Protocol.create(
                        parts[1].toCharArray(), Protocol.Realm(parts[2], parts[3]),
                        cc, cs, passwordCallback, size
                    )
                } catch (e: NumberFormatException) {
                    pw.println("Invalid size")
                }
            }
            "get", "change" -> {
                if (parts.size < 4) {
                    pw.println("Not enough arguments")
                }
                val realm = Protocol.Realm(parts[2], parts[3])
                if (parts[0] == "get") {
                    Protocol.get(parts[1].toCharArray(), realm, cs, passwordCallback)
                } else {
                    Protocol.change(parts[1].toCharArray(), realm, cs, passwordCallback)
                }
            }
            "commit", "delete" -> {
                if (parts.size < 3) {
                    pw.println("Not enough arguments")
                }
                val realm = Protocol.Realm(parts[1], parts[2])
                if (parts[0] == "commit") {
                    Protocol.commit(realm, cs, oneWayCallback)
                } else {
                    Protocol.delete(realm, cs)
                }
            }
            "list" -> {
                Protocol.list(parts[1], cs).forEach(pw::println)
            }
            else -> pw.println("Unknown command")
        }
    } catch (s: Protocol.ServerFailureException) {
        pw.println("Server failure")
    }
}