package org.hsbp.androsphinx

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry

import org.junit.Test
import org.junit.runner.RunWith

import org.junit.Assert.*
import java.io.PrintWriter
import java.lang.NumberFormatException
import java.net.ServerSocket
import java.util.*

/**
 * Instrumented test, which will execute on an Android device.
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 *
 * SPDX-FileCopyrightText: 2019, Andras Veres-Szentkiralyi <vsza@vsza.hu>
 * SPDX-License-Identifier: MIT
 */

@Suppress("SpellCheckingInspection")
const val EXPECTED_BASIC_TEST = "ytPIZvsZlQAr/9nLg4MX0g2F+U0V6K141xEECIwNLEA="

@RunWith(AndroidJUnit4::class)
class ExampleInstrumentedTest {
    @Test
    fun sphinxBasicTest() {
        val salt = ByteArray(16) { 0 }
        salt[0] = 1
        Sphinx.Challenge("shitty password".toCharArray(), salt).use { c ->
            val secret = ByteArray(32) { 0 }
            secret[0] = 1
            val resp = Sphinx.respond(c.challenge, secret)!!
            val rwd = c.finish(salt, resp)!!
            assertArrayEquals(Base64.decode(EXPECTED_BASIC_TEST, Base64.DEFAULT), rwd)
        }
    }

    @Test
    fun storageTest() {
        val appContext = InstrumentationRegistry.getInstrumentation().targetContext
        val storage = AndroidCredentialStore(appContext)
        val key = storage.key
        assertEquals(MASTER_KEY_BYTES, key.asBytes.size)
        assertArrayEquals(storage.key.asBytes, key.asBytes)

        assertEquals("", storage.host)
        assertEquals(0, storage.port)

        val host = "example.tld"
        val port = 31337
        appContext.storeServerInfo(host, port)

        assertEquals(host, storage.host)
        assertEquals(port, storage.port)
    }

    @Test
    fun sphinxNetworkTest() {
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

        callback.gotPassword = null

        Protocol.commit("sphinxNetworkTestMasterPassword".toCharArray(), realm, cs, callback)
        assertArrayEquals(pw2, callback.gotPassword)

        callback.gotPassword = null

        Protocol.get("sphinxNetworkTestMasterPassword".toCharArray(), realm, cs, callback)
        assertArrayEquals(pw2, callback.gotPassword)

        callback.gotPassword = null

        Protocol.undo("sphinxNetworkTestMasterPassword".toCharArray(), realm, cs, callback)
        assertArrayEquals(pw, callback.gotPassword)

        callback.gotPassword = null

        Protocol.get("sphinxNetworkTestMasterPassword".toCharArray(), realm, cs, callback)
        assertArrayEquals(pw, callback.gotPassword)

        Protocol.delete("sphinxNetworkTestMasterPassword".toCharArray(), realm, cs)
        val userList3 = Protocol.list(hostname, cs)
        assertEquals(1, userList3.size)
        assert(userList3.contains(username2))

        try {
            Protocol.get("sphinxNetworkTestMasterPassword".toCharArray(), realm, cs, callback)
            fail("ServerFailureException should've been thrown")
        } catch (e: Protocol.ServerFailureException) {
            // success
        }
    }

    @Test
    @Suppress("SpellCheckingInspection")
    fun readEvalPrintLoopTest() {
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
        pw.println("<get|change|commit|delete> <master password> <user> <site>")
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
                        EnumSet.noneOf(CharacterClass::class.java)
                    ) { it.name[0].toLowerCase() in ccs }
                    Protocol.create(
                        parts[1].toCharArray(), Protocol.Realm(parts[2], parts[3]),
                        cc, cs, passwordCallback, size
                    )
                } catch (e: NumberFormatException) {
                    pw.println("Invalid size")
                }
            }
            "get", "change", "commit", "delete" -> {
                if (parts.size < 4) {
                    pw.println("Not enough arguments")
                }
                val realm = Protocol.Realm(parts[2], parts[3])
                when (parts[0]) {
                    "get"    -> Protocol.get(   parts[1].toCharArray(), realm, cs, passwordCallback)
                    "change" -> Protocol.change(parts[1].toCharArray(), realm, cs, passwordCallback)
                    "commit" -> Protocol.commit(parts[1].toCharArray(), realm, cs, passwordCallback)
                    "delete" -> Protocol.delete(parts[1].toCharArray(), realm, cs)
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
