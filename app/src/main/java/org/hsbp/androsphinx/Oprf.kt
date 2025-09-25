package org.hsbp.androsphinx

import android.os.Build
import androidx.annotation.RequiresApi
import java.lang.ref.Cleaner

class Oprf {
    companion object {
        init {
            System.loadLibrary("oprf")
            System.loadLibrary("sphinx")
        }

        @JvmStatic external fun blind(inputValue: ByteArray): Pair<ByteArray, ByteArray>
        @JvmStatic external fun evaluate(key: ByteArray, blinded: ByteArray): ByteArray
        @JvmStatic external fun unblindFinalize(r: ByteArray, z: ByteArray, x: ByteArray): ByteArray
        @JvmStatic external fun thresholdMult(responses: List<ByteArray>): ByteArray
        @JvmStatic external fun scalarMultRistretto255base(r: ByteArray): ByteArray?
        @JvmStatic external fun tpDkgStartTp(n: Byte, t: Byte, tsEpsilon: Long, protoName: String, peerLongTermPublicKeys: List<ByteArray>): Pair<TpdkgContext, ByteArray>
        @JvmStatic external fun tpDkgPeerStart(tsEpsilon: Long, peerLongTermSecretKey: ByteArray, msg0: ByteArray): TpdkgPeerContext
    }
}

class TpdkgContext(context: Long, buf: Long) : AutoCloseable {
    private var ctx: Long = context
    @RequiresApi(Build.VERSION_CODES.TIRAMISU) // TODO app min API level?
    private var cleanable = cleaner.register(this) {
        dispose(context, buf)
    }

    companion object {
        @RequiresApi(Build.VERSION_CODES.TIRAMISU)
        val cleaner: Cleaner = Cleaner.create()
        @JvmStatic external fun dispose(context: Long, buf: Long)
    }

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
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
    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private var cleanable = cleaner.register(this) {
        dispose(context, buf)
    }

    companion object {
        @RequiresApi(Build.VERSION_CODES.TIRAMISU)
        val cleaner: Cleaner = Cleaner.create()
        @JvmStatic external fun dispose(context: Long, buf: Long)
    }

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
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
