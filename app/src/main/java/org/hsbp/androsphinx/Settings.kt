package org.hsbp.androsphinx

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.text.InputType
import android.util.AttributeSet
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.preference.EditTextPreference
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import com.google.zxing.integration.android.IntentIntegrator
import org.libsodium.jni.Sodium
import java.nio.ByteBuffer
import java.nio.ByteOrder
import android.graphics.Bitmap
import android.graphics.Point
import android.graphics.drawable.BitmapDrawable
import android.widget.ImageView
import androidx.appcompat.app.AlertDialog
import androidx.preference.SwitchPreference
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import java.util.*
import kotlin.experimental.or

class SettingsActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)
        supportFragmentManager
            .beginTransaction()
            .replace(R.id.settings_container, SettingsFragment())
            .commit()
    }
}

const val QR_FLAGS_HAS_KEY: Int = 1
const val QR_FLAGS_USE_TLS: Int = 2
const val BLACK: Int = 0xFF000000.toInt()
const val WHITE: Int = 0xFFFFFFFF.toInt()

class SettingsFragment : PreferenceFragmentCompat() {
    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        setPreferencesFromResource(R.xml.preferences, rootKey)
        preferenceManager.findPreference<Preference>("scan_qr")!!.setOnPreferenceClickListener {
            IntentIntegrator(this).initiateScan()
            true
        }
        ShareType.values().forEach { t ->
            val p = preferenceManager.findPreference<Preference>(t.key)!!
            p.setOnPreferenceClickListener {
                showQR(t.serialize(requireContext()), p.title)
                true
            }
        }
    }

    private fun showQR(payload: ByteArray, title: CharSequence) {
        val display = requireActivity().windowManager.defaultDisplay
        val size = Point()
        display.getSize(size)
        val dimension = size.x.coerceAtMost(size.y) / 4 * 3
        val result = QRCodeWriter().encode(payload, BarcodeFormat.QR_CODE, dimension, dimension)
        val w = result.width
        val h = result.height
        val pixels = IntArray(w * h) { i -> if (result[i.rem(w), i / w]) BLACK else WHITE }
        val bm = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
        bm.setPixels(pixels, 0, w, 0, 0, w, h)
        with(AlertDialog.Builder(requireContext())) {
            setTitle(title)
            setView(ImageView(context).apply {
                setImageDrawable(BitmapDrawable(requireActivity().resources, bm))
            })
            setNeutralButton(android.R.string.ok, null)
            show()
        }
    }

    @Suppress("UsePropertyAccessSyntax")
    @SuppressLint("MissingSuperCall")
    @ExperimentalStdlibApi
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val ir = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
        val info = ByteBuffer.wrap(ir.byteSegments0).order(ByteOrder.BIG_ENDIAN)

        try {
            val formatFlags = info.get().toInt()
            val masterKey = if (formatFlags and QR_FLAGS_HAS_KEY == QR_FLAGS_HAS_KEY) {
                MasterKey.fromByteBuffer(info)
            } else {
                null
            }
            val port = info.getShort()
            val host = info.getByteArray(info.remaining()).decodeToString()

            with(preferenceManager) {
                findPreference<EditTextPreference>(SHARED_PREFERENCES_KEY_HOST)!!.text = host
                findPreference<IntEditTextPreference>(SHARED_PREFERENCES_KEY_PORT)!!.text = port.toString()
                findPreference<SwitchPreference>(SHARED_PREFERENCES_KEY_USE_TLS)!!.isChecked = (formatFlags and QR_FLAGS_USE_TLS == QR_FLAGS_USE_TLS)
            }

            if (masterKey != null) {
                AndroidCredentialStore(requireContext()).writeMasterKey(masterKey)
            }

            Toast.makeText(context, R.string.scan_qr_done, Toast.LENGTH_LONG).show()
        } catch (e: Exception) {
            e.printStackTrace()
            Toast.makeText(context, R.string.scan_qr_error, Toast.LENGTH_LONG).show()
        }
    }
}

enum class ShareType(private val code: Byte) {
    @Suppress("UNUSED") PUBLIC(code = 0),
    @Suppress("UNUSED") PRIVATE(code = QR_FLAGS_HAS_KEY.toByte()) {
        override val privateMaterialSize: Int
            get() = Sodium.crypto_sign_secretkeybytes()

        override fun providePrivateMaterial(target: ByteBuffer, cs: Protocol.CredentialStore) {
            target.put(cs.key.asBytes)
        }
    };

    open fun providePrivateMaterial(target: ByteBuffer, cs: Protocol.CredentialStore) {}
    open val privateMaterialSize: Int
        get() = 0

    val key: String
        get() = "share_qr_${name.toLowerCase(Locale.ROOT)}"

    fun serialize(context: Context): ByteArray {
        val cs = AndroidCredentialStore(context)
        val hostBytes = cs.host.toByteArray()
        val info = ByteBuffer.allocate(1 + 2 + hostBytes.size + privateMaterialSize)

        with(info) {
            put(code or (if (cs.useTls) QR_FLAGS_USE_TLS.toByte() else 0))
            providePrivateMaterial(info, cs)
            putShort(cs.port.toShort())
            put(hostBytes)
        }

        return info.array()
    }
}

private fun ByteBuffer.getByteArray(length: Int): ByteArray {
    val result = ByteArray(length)
    get(result)
    return result
}

class IntEditTextPreference : EditTextPreference {
    @Suppress("UNUSED")
    constructor(context: Context) : super(context)
    @Suppress("UNUSED")
    constructor(context: Context, attrs: AttributeSet) : super(context, attrs)
    @Suppress("UNUSED")
    constructor(context: Context, attrs: AttributeSet, defStyle: Int) : super(context, attrs, defStyle)
    @Suppress("UNUSED")
    constructor(context: Context, attrs: AttributeSet, defStyle: Int, defStyleRes: Int) : super(context, attrs, defStyle, defStyleRes)

    init {
        setOnBindEditTextListener { editText ->
            editText.inputType = InputType.TYPE_CLASS_NUMBER
        }
    }

    override fun getPersistedString(defaultReturnValue: String?): String = getPersistedInt(0).toString()
    override fun persistString(value: String): Boolean = persistInt(value.toIntOrNull() ?: 0)
}