package org.hsbp.androsphinx

import com.github.michaelbull.itertools.tripleCombinations
import java.lang.ref.Cleaner
import java.util.*

const val SPHINX_255_SCALAR_BYTES: Int = 32
const val SPHINX_255_SER_BYTES: Int = 32
const val DECAF_255_SER_BYTES: Int = 32
const val CRYPTO_GENERICHASH_BYTES: Int = 32
const val CRYPTO_SIGN_SECRETKEYBYTES: Int = 64
const val CRYPTO_SIGN_PUBLICKEYBYTES: Int = 32
const val CRYPTO_SIGN_SEEDBYTES: Int = 32
const val CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES: Int = 32
const val CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES: Int = 24
const val CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES: Int = 16

class Oprf {
    companion object {
        init {
            System.loadLibrary("oprf")
            System.loadLibrary("sphinx")
            //System.loadLibrary("frida")
        }

        @JvmStatic external fun blind(inputValue: ByteArray): Pair<ByteArray, ByteArray>
        @JvmStatic external fun evaluate(key: ByteArray, blinded: ByteArray): ByteArray
        @JvmStatic external fun unblindFinalize(r: ByteArray, z: ByteArray, x: ByteArray): ByteArray
        @JvmStatic external fun thresholdMult(responses: List<ByteArray>): ByteArray
        @JvmStatic external fun scalarMultRistretto255base(r: ByteArray): ByteArray?
        @JvmStatic external fun tpDkgStartTp(n: Byte, t: Byte, tsEpsilon: Long, protoName: String, peerLongTermPublicKeys: List<ByteArray>): Pair<TpdkgContext, ByteArray>
        @JvmStatic external fun tpDkgPeerStart(tsEpsilon: Long, peerLongTermSecretKey: ByteArray, msg0: ByteArray): TpdkgPeerContext


        @OptIn(ExperimentalStdlibApi::class)
        @JvmStatic
        fun main(args: Array<String>) {
            println("Hello World!")
            /*val s: Scanner = Scanner(System.`in`)
            println("Press enter to continue.....")
            s.nextLine()
            val result = Oprf.Companion.blind("\u0000".toByteArray())
            println("${result.first.toList()}, ${result.second.toList()}")*/
            val x = "00".hexToByteArray()
            val k = "5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e".hexToByteArray()
            val out = "527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6".hexToByteArray()
            val (r, alpha) = blind(x)
            val beta = evaluate(k, alpha)
            val y = unblindFinalize(r, beta, x)
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
            val (tp, msg0) = tpDkgStartTp(n, t, tsEpsilon, "pyoprf tpdkg test", peerLongTermPublicKeys)
            tp.use {
                println("tp: $tp")
                println("n: ${tp.n}")
                println("t: ${tp.t}")
                println("sid: ${tp.sessionId?.toHexString()}")
                val peers = peerLongTermSecretKeys.map { sk ->
                    tpDkgPeerStart(tsEpsilon, sk, msg0)
                }
                peers.zip(peerLongTermSecretKeys).forEach { (peer, sk) ->
                    println(peer.sessionId contentEquals tp.sessionId)
                    println(peer.longTermSecretKey contentEquals sk)
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
                val v0 = thresholdMult((0..2).map { i ->
                    ByteArray(1) { (i + 1).toByte() } +
                            scalarMultRistretto255base(shares[i].copyOfRange(1, shares[i].size))!!})
                println(v0.toHexString())
                (1..<n).toList().tripleCombinations().forEach { peerIndexes ->
                    val v1 = thresholdMult(peerIndexes.toList().map { i ->
                        ByteArray(1) { (i + 1).toByte() } +
                                scalarMultRistretto255base(shares[i].copyOfRange(1, shares[i].size))!!
                    })
                    println("${v0 contentEquals v1} $peerIndexes\t${v1.toHexString()}")
                }
            }
            println("msg0: ${msg0.toHexString()}")
        }
    }
}

class TpdkgContext(context: Long, buf: Long) : AutoCloseable {
    private var ctx: Long = context
    private var cleanable: Cleaner.Cleanable = cleaner.register(this) {
        dispose(context, buf)
    }

    companion object {
        val cleaner: Cleaner = Cleaner.create()
        @JvmStatic external fun dispose(context: Long, buf: Long)
    }

    override fun close() {
        cleanable.clean()
    }

    val n: Byte
        external get

    val t: Byte
        external get

    val sessionId: ByteArray?
        external get

    val isNotDone: Boolean
        external get

    val inputSizes: LongArray?
        external get

    val step: Int
        external get

    external fun next(msg: ByteArray): ByteArray?
    external fun peerMessage(base: ByteArray, peer: Byte): ByteArray?

    @OptIn(ExperimentalStdlibApi::class)
    override fun toString(): String {
        return "TpdkgContext@${ctx.toHexString()}"
    }
}

class TpdkgPeerContext(context: Long, buf: Long) : AutoCloseable { // TODO trusted party
    private var ctx: Long = context
    private var cleanable: Cleaner.Cleanable = cleaner.register(this) {
        dispose(context, buf)
    }

    companion object {
        val cleaner: Cleaner = Cleaner.create()
        @JvmStatic external fun dispose(context: Long, buf: Long)
    }

    override fun close() {
        cleanable.clean()
    }

    external fun next(msg: ByteArray): ByteArray?

    val sessionId: ByteArray?
        external get

    val longTermSecretKey: ByteArray?
        external get

    val isNotDone: Boolean
        external get

    val share: ByteArray
        external get

    @OptIn(ExperimentalStdlibApi::class)
    override fun toString(): String {
        return "TpdkgPeerContext@${ctx.toHexString()}"
    }
}

fun main() {
    println("Hello World!")
    val p = Pair(5, 6)
    Oprf.Companion.blind("foobar".toByteArray())
}

class Sodium {
    companion object {
        @JvmStatic external fun genericHash(message: ByteArray, salt: ByteArray,
                                            outputLength: Int = CRYPTO_GENERICHASH_BYTES): ByteArray
        @JvmStatic external fun randomBytes(amount: Int): ByteArray
        @JvmStatic external fun cryptoSignSeedKeypair(seed: ByteArray): ByteArray
        @JvmStatic external fun cryptoSignEd25519SkToPk(sk: ByteArray): ByteArray
        @JvmStatic external fun cryptoSignDetached(sk: ByteArray, msg: ByteArray): ByteArray
        @JvmStatic external fun cryptoAeadXchachaPoly1305IetfEasy(msg: ByteArray, ad: ByteArray, key: ByteArray): ByteArray?
        @JvmStatic external fun cryptoAeadXchachaPoly1305IetfOpenEasy(msg: ByteArray, ad: ByteArray, key: ByteArray): ByteArray?
    }
}