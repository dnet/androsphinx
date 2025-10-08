package org.hsbp.androsphinx

class Oprf {
    companion object {
        init {
            System.loadLibrary("oprf")
            System.loadLibrary("sphinx")
        }

        @JvmStatic external fun blind(inputValue: ByteArray): Pair<ByteArray, ByteArray>
        @JvmStatic external fun evaluate(key: ByteArray, blinded: ByteArray): ByteArray
        @JvmStatic external fun unblindFinalize(r: ByteArray, z: ByteArray, x: ByteArray): ByteArray?
        @JvmStatic external fun thresholdMult(responses: List<ByteArray>): ByteArray
        @JvmStatic external fun scalarMultRistretto255base(r: ByteArray): ByteArray?
        @JvmStatic external fun tpDkgStartTp(n: Byte, t: Byte, tsEpsilon: Long, protoName: String, peerLongTermPublicKeys: List<ByteArray>): Pair<TpdkgContext, ByteArray>
        @JvmStatic external fun tpDkgPeerStart(tsEpsilon: Long, peerLongTermSecretKey: ByteArray, msg0: ByteArray): TpdkgPeerContext
    }
}

class TpdkgContext(private var ctx: Long, private var buf: Long) : AutoCloseable {
    companion object {
        @JvmStatic external fun dispose(context: Long, buf: Long)
    }

    override fun close() {
        if (buf != 0L && ctx != 0L) {
            dispose(ctx, buf)
            ctx = 0L
            buf = 0L
        }
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

class TpdkgPeerContext(private var ctx: Long, private var buf: Long) : AutoCloseable { // TODO trusted party
    companion object {
        @JvmStatic external fun dispose(context: Long, buf: Long)
    }

    override fun close() {
        if (buf != 0L && ctx != 0L) {
            dispose(ctx, buf)
            ctx = 0L
            buf = 0L
        }
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
