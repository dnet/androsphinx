package org.hsbp.androsphinx

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.github.michaelbull.itertools.tripleCombinations
import org.hsbp.equihash.Equihash

import org.junit.Test
import org.junit.runner.RunWith

import org.junit.Assert.*
import java.io.PrintWriter
import java.lang.NumberFormatException
import java.net.ServerSocket
import java.util.*
import kotlin.experimental.xor

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
@Suppress("SpellCheckingInspection")
const val EXPECTED_SOL = "AAAAAla2ZzCKSqru43jruW0FQAcmV0tdnJNE9r2ovD7R/BfjIVK2zg+STcclSSYqeTXUvUBVbzOL4Q4Im9W66oPk8XLcvqJVywe5dA=="

@RunWith(AndroidJUnit4::class)
class ExampleInstrumentedTest {
    @Test
    fun oprfBasicTest() {
        val x = "00".hexToByteArray()
        val k = "5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e".hexToByteArray()
        val out = "527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6".hexToByteArray()
        val (r, alpha) = Oprf.blind(x)
        val beta = Oprf.evaluate(k, alpha)
        val y = Oprf.unblindFinalize(r, beta, x)
        println("match? ${y.contentEquals(out)}")

        val n: Byte = 5
        val t: Byte = 3
        val tsEpsilon: Long = 5
        val peerLongTermSecretKeys = (1..n).map { Sodium.cryptoSignSeedKeypair(Sodium.randomBytes(CRYPTO_SIGN_SEEDBYTES)) }
        val peerLongTermPublicKeys = peerLongTermSecretKeys.map(Sodium::cryptoSignEd25519SkToPk)
        println("Public keys:")
        peerLongTermPublicKeys.forEach {
            println(" - ${it.toHexString()}")
        }
        val (tp, msg0) = Oprf.tpDkgStartTp(n, t, tsEpsilon, "pyoprf tpdkg test", peerLongTermPublicKeys)
        tp.use {
            println("tp: $tp")
            println("n: ${tp.n}")
            println("t: ${tp.t}")
            println("sid: ${tp.sessionId?.toHexString()}")
            val peers = peerLongTermSecretKeys.map { sk ->
                Oprf.tpDkgPeerStart(tsEpsilon, sk, msg0)
            }
            peers.zip(peerLongTermSecretKeys).forEach { (peer, sk) ->
                assertArrayEquals(peer.sessionId, tp.sessionId)
                assertArrayEquals(peer.longTermSecretKey, sk)
            }
            val peerMessages = mutableListOf<ByteArray>()
            while (tp.isNotDone) {
                println("---while---")
                val messages = if (peerMessages.isEmpty()) ByteArray(0) else peerMessages.reduce { acc, bytes -> acc + bytes }
                println(tp.inputSizes?.joinToString())
                val curStep = tp.step
                var tpOut = tp.next(messages)!!
                println("curStep = $curStep, tpOut = ${tpOut.toHexString()}")
                peerMessages.clear()
                while ((peerMessages.isEmpty() or peerMessages.all(ByteArray::isEmpty)) and peers[0].isNotDone) {
                    peers.forEachIndexed { peerIndex, peer ->
                        val msg = if (tpOut.isEmpty()) {
                            ByteArray(0)
                        } else {
                            tp.peerMessage(tpOut, peerIndex.toByte())!!
                        }
                        println(msg.toHexString())
                        val outMsg = peer.next(msg)!!
                        if (outMsg.isNotEmpty()) peerMessages.add(outMsg)
                    }
                    tpOut = ByteArray(0)
                }
            }
            val shares = peers.map { it.share }
            shares.forEachIndexed { i, share ->
                println("share[${i+1}] ${share.toHexString()}")
            }
            val v0 = Oprf.thresholdMult((0..2).map { i ->
                ByteArray(1) { (i + 1).toByte() } +
                        Oprf.scalarMultRistretto255base(shares[i].copyOfRange(1, shares[i].size))!!})
            println(v0.toHexString())
            (1..<n).toList().tripleCombinations().forEach { peerIndexes ->
                val v1 = Oprf.thresholdMult(peerIndexes.toList().map { i ->
                    ByteArray(1) { (i + 1).toByte() } +
                            Oprf.scalarMultRistretto255base(shares[i].copyOfRange(1, shares[i].size))!!
                })
                assertArrayEquals(v0, v1)
                println("${v0 contentEquals v1} $peerIndexes\t${v1.toHexString()}")
            }
        }
        println("msg0: ${msg0.toHexString()}")
    }

    @Test
    fun checkDigitCalcTest() {
        val h = Protocol.calculateCheckDigit("bar".toByteArray())
        assertEquals(h.toLong(), 0x86)
    }

    @Test
    fun aeadTest() {
        val cs = MockCredentialStore()
        val key = cs.getSealKey()
        val plaintext = Base64.decode(EXPECTED_BASIC_TEST, Base64.DEFAULT)
        val expectedVersion = 0.toByte()
        val ciphertext = key.encrypt(plaintext)
        assertEquals(expectedVersion, ciphertext[0])
        val (version, decrypted) = key.decrypt(ciphertext)
        assertEquals(expectedVersion, version)
        assertArrayEquals(plaintext, decrypted)
        ciphertext[0] = 1
        try {
            key.decrypt(ciphertext)
            fail("SodiumException should've been thrown")
        } catch (e: SodiumException) {
            // success
        }
        val expectedLength = plaintext.size + 1 + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES + CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES
        assertEquals(expectedLength, ciphertext.size)
    }

    @Test
    fun equihashBasicTest() {
        val n = 102
        val k = 5
        val seed = "some initial seed".toByteArray()
        val sol = Equihash.solve(n, k, seed)
        if (sol == null) {
            fail("sol == null")
        } else {
            assertArrayEquals(Base64.decode(EXPECTED_SOL, Base64.DEFAULT), sol)
            assert(Equihash.verify(n, k, seed, sol))
            sol[16] = sol[16].xor(1)
            assertFalse(Equihash.verify(n, k, seed, sol))
        }
    }

    @Test
    fun settingsSerializationTest() {
        val cs = MockCredentialStore()
        val bytes = ShareType.PRIVATE.serialize(cs)
        val parsed = SerializedCredentialStore(bytes)
        assert(cs.key.contentEquals(parsed.key))
        assertEquals(cs.rwdKeys, parsed.rwdKeys)
        assertEquals(cs.threshold, parsed.threshold)
        assertEquals(cs.servers, parsed.servers)
    }

    @Test
    fun storageTest() {
        val appContext = InstrumentationRegistry.getInstrumentation().targetContext
        try {
            AndroidCredentialStore(appContext).key
            fail("FileNotFoundException should have been thrown")
        } catch (_: java.io.FileNotFoundException) {
            // expected
        }
        val mock = MockCredentialStore()
        AndroidCredentialStore(appContext).updateSettings(mock)
        val storage = AndroidCredentialStore(appContext)
        val key = storage.key
        assertEquals(MASTER_KEY_BYTES, key.asBytes.size)
        assertArrayEquals(storage.key.asBytes, key.asBytes)
        assertArrayEquals(key.asBytes, mock.key.asBytes)

        assertEquals(mock.servers, storage.servers)
        assertEquals(mock.rwdKeys, storage.rwdKeys)
        assertEquals(mock.threshold, storage.threshold)
    }

    @Test
    fun sphinxNetworkTest() {
        val username = "network"
        val username2 = "network2"
        val charClasses = setOf(CharacterClass.LOWER, CharacterClass.DIGITS)
        val size = 18

        for ((n, t) in listOf(1 to 1, 5 to 3)) {
            println("====== n = $n, t = $t ======")
            val cs = MockCredentialStore(n, t)
            val hostname = "test${System.currentTimeMillis()}.tld"
            val realm = Protocol.Realm(username, hostname)
            val realm2 = Protocol.Realm(username2, hostname)

            assert(Protocol.list(hostname, cs).isEmpty())

            val symbolSet = SYMBOL_SET.substring(0 .. SYMBOL_SET.length / 2).toSet()
            val pw = Protocol.create("sphinxNetworkTestMasterPassword".toCharArray(), realm, charClasses, cs, symbolSet, size)
            assertEquals(size, pw.length)
            assert(pw.all { pwChar -> charClasses.any { it.range?.contains(pwChar) ?: false } or (pwChar in symbolSet) })
            val userList = Protocol.list(hostname, cs)
            assertEquals(1, userList.size)
            assert(userList.contains(username))

            Protocol.create("sphinxNetworkTestMasterPassword2".toCharArray(), realm2, charClasses, cs, symbolSet, size)
            val userList2 = Protocol.list(hostname, cs)
            assertEquals(2, userList2.size)
            assert(userList2.contains(username))
            assert(userList2.contains(username2))

            val (gr, pwGet) = Protocol.get("sphinxNetworkTestMasterPassword".toCharArray(), realm, cs)
            assertEquals(pw, pwGet)
            assertEquals(gr.charClasses, charClasses)
            assertEquals(gr.size.toInt(), size)

            val pwChanged = Protocol.change("sphinxNetworkTestMasterPassword".toCharArray(), realm, charClasses, cs, emptySet(), size)
            assertFalse(pwChanged.contentEquals(pwGet))

            val (_, pwBeforeCommit) = Protocol.get("sphinxNetworkTestMasterPassword".toCharArray(), realm, cs)
            assertEquals(pw, pwBeforeCommit)

            Protocol.commit("sphinxNetworkTestMasterPassword".toCharArray(), realm, cs)

            val (_, pwAfterCommit) = Protocol.get("sphinxNetworkTestMasterPassword".toCharArray(), realm, cs)
            assertEquals(pwChanged, pwAfterCommit)

            Protocol.undo("sphinxNetworkTestMasterPassword".toCharArray(), realm, cs)

            val (_, pwAfterUndo) = Protocol.get("sphinxNetworkTestMasterPassword".toCharArray(), realm, cs)
            assertEquals(pw, pwAfterUndo)

            Protocol.delete("sphinxNetworkTestMasterPassword".toCharArray(), realm, cs)
            val userList3 = Protocol.list(hostname, cs)
            assertEquals(1, userList3.size)
            assert(userList3.contains(username2))

            try {
                Protocol.get("sphinxNetworkTestMasterPassword".toCharArray(), realm, cs)
                fail("ServerFailureException should've been thrown")
            } catch (e: Protocol.ServerFailureException) {
                // success
            }
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
        pw.println("<create|change> <master password> <user> <site> [u][l][d][s] [<size>]")
        pw.println("<get|commit|delete> <master password> <user> <site>")
        pw.println("list <site>")
        return
    }

    val parts = cmd.split(' ')
    if (parts.size < 2) {
        pw.println("Not enough arguments or unknown command")
        return
    }

    try {
        when (parts[0]) {
            "create", "change" -> {
                if (parts.size < 5) {
                    pw.println("Not enough arguments")
                }
                try {
                    val size = if (parts.size > 5) parts[5].toInt() else 0
                    val ccs = parts[4].lowercase(Locale.ROOT)
                    val cc = CharacterClass.entries.filterTo(
                        EnumSet.noneOf(CharacterClass::class.java)
                    ) { it.name[0].lowercaseChar() in ccs }
                    val realm = Protocol.Realm(parts[2], parts[3])
                    val symbols = if ('s' in ccs) SYMBOL_SET.toSet() else emptySet()
                    val derived = if (parts[0] == "create") {
                        Protocol.create(
                            parts[1].toCharArray(), realm, cc, cs, symbols, size)
                    } else {
                        Protocol.change(
                            parts[1].toCharArray(), realm, cc, cs, symbols, size)
                    }
                    pw.println(derived)
                } catch (e: NumberFormatException) {
                    pw.println("Invalid size")
                }
            }
            "get", "commit", "delete" -> {
                if (parts.size < 4) {
                    pw.println("Not enough arguments")
                }
                val realm = Protocol.Realm(parts[2], parts[3])
                when (parts[0]) {
                    "get"    -> pw.println(
                                   Protocol.get(parts[1].toCharArray(), realm, cs).second)
                    "commit" -> Protocol.commit(parts[1].toCharArray(), realm, cs)
                    "delete" -> Protocol.delete(parts[1].toCharArray(), realm, cs)
                }
            }
            "list" -> {
                Protocol.list(parts[1], cs).forEach(pw::println)
            }
            else -> pw.println("Unknown command")
        }
    } catch (_: Protocol.ServerFailureException) {
        pw.println("Server failure")
    }
}
