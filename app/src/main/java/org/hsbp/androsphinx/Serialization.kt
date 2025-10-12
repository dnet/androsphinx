package org.hsbp.androsphinx

import android.content.Context
import com.danrusu.pods4k.immutableArrays.ImmutableByteArray
import com.danrusu.pods4k.immutableArrays.toMutableArray
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Locale
import java.util.zip.DeflaterOutputStream
import java.util.zip.InflaterInputStream
import kotlin.experimental.and
import kotlin.io.use

const val QR_FLAGS_HAS_KEY: Int = 1
const val QR_FLAGS_RWD_KEYS: Int = 2
const val QR_FLAGS_VALIDATE_PASSWORD: Int = 4 // TODO
const val QR_FLAGS_USERLIST: Int = 8 // TODO not really usable on Android, maybe ask the user for name?

class SerializedCredentialStore(private val bytes: ByteArray) : Protocol.CredentialStore {
    override val key: MasterKey
        get() {
            check(hasKey, { "Flags indicate lack of key material in serialized bytes" })
            return MasterKey.fromByteArray(bytes.sliceArray(2 until 2 + MASTER_KEY_BYTES))
        }
    override val servers: List<Protocol.Server>
        get() = serverList
    override val rwdKeys: Boolean
        get() = (flags and QR_FLAGS_RWD_KEYS) == QR_FLAGS_RWD_KEYS
    override val threshold: Int
        get() = bytes[1].toInt()

    private val flags: Int
        get() = bytes[0].toInt()
    val hasKey: Boolean
        get() = (flags and QR_FLAGS_HAS_KEY == QR_FLAGS_HAS_KEY)

    private val serverList: List<Protocol.Server>

    init {
        ByteArrayInputStream(bytes).use { qr ->
            qr.skip(if (hasKey) 2L + MASTER_KEY_BYTES else 2L) // flags + threshold + keys?
            val serverCount = qr.read()
            val keys = (1..serverCount).map {
                qr.readNBytes(CRYPTO_SIGN_PUBLICKEYBYTES)
            }
            InflaterInputStream(qr).use { decompressed ->
                serverList = keys.map { key ->
                    val name = decompressed.readPascalString()
                    val host = decompressed.readPascalString()
                    val portHigh = decompressed.read() shl 8
                    val port = decompressed.read() or portHigh
                    Protocol.Server(name, host, port,
                        ImmutableByteArray.copyFrom(
                            key, 0, CRYPTO_SIGN_PUBLICKEYBYTES))
                }
            }
        }
    }

    companion object {
        fun fromQrRawBytes(bytes: ByteArray): SerializedCredentialStore {
            val bignum = BigInteger(POSITIVE, bytes) shr 4
            val bb = ByteBuffer.wrap(bignum.toByteArray()).order(ByteOrder.BIG_ENDIAN)
            check(bb.get() == 4.toByte(), { "Only binary QR codes are supported" })
            val length = if (bytes.size < 0x100) bb.get().toInt() else bb.getShort().toInt()
            val payload = ByteArray(length)
            bb.get(payload)
            return SerializedCredentialStore(payload)
        }
    }
}

enum class ShareType(private val code: Int) {
    @Suppress("UNUSED") PUBLIC(code = 0),
    @Suppress("UNUSED") PRIVATE(code = QR_FLAGS_HAS_KEY) {
        override fun providePrivateMaterial(target: OutputStream, cs: Protocol.CredentialStore) {
            target.write(cs.key.asBytes)
        }
    };

    open fun providePrivateMaterial(target: OutputStream, cs: Protocol.CredentialStore) {}
    val key: String
        get() = "share_qr_${name.lowercase(Locale.ROOT)}"

    fun serialize(context: Context): ByteArray {
        val cs = AndroidCredentialStore(context)
        return serialize(cs)
    }

    fun serialize(cs: Protocol.CredentialStore): ByteArray = ByteArrayOutputStream().use { qr ->
        qr.write(if (cs.rwdKeys) (code or QR_FLAGS_RWD_KEYS) else code)
        qr.write(cs.threshold)
        providePrivateMaterial(qr, cs)
        qr.write(cs.servers.size)
        cs.servers.forEach { server ->
            qr.write(server.longTermSignatureKey.toMutableArray())
        }
        DeflaterOutputStream(qr).use { compressed ->
            cs.servers.forEach { server ->
                compressed.writePascalString(server.name)
                compressed.writePascalString(server.host)
                compressed.write(server.port shr 8)
                compressed.write(server.port and 0xFF)
            }
        }
        return qr.toByteArray()
    }
}

private fun OutputStream.writePascalString(name: String) {
    val bytes = name.toByteArray()
    check(bytes.size < 256)
    write(bytes.size)
    write(bytes)
}

private fun InputStream.readPascalString(): String {
    val length = read()
    return readNBytes(length).decodeToString()
}