package org.hsbp.androsphinx

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.text.InputType
import android.util.AttributeSet
import android.util.Base64
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.preference.EditTextPreference
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import com.google.zxing.integration.android.IntentIntegrator
import org.libsodium.jni.Sodium
import java.nio.ByteBuffer
import java.nio.ByteOrder

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

const val QR_FLAGS_HAS_KEY_SALT: Int = 1

class SettingsFragment : PreferenceFragmentCompat() {
    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        setPreferencesFromResource(R.xml.preferences, rootKey)
        preferenceManager.findPreference<Preference>("scan_qr")!!.setOnPreferenceClickListener {
            IntentIntegrator(this).initiateScan()
            true
        }
    }

    @SuppressLint("MissingSuperCall")
    @ExperimentalStdlibApi
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val ir = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
        val info = ByteBuffer.wrap(ir.byteSegments0).order(ByteOrder.BIG_ENDIAN)

        try {
            val formatFlags = info.get().toInt()
            val secrets = if (formatFlags and QR_FLAGS_HAS_KEY_SALT == QR_FLAGS_HAS_KEY_SALT) {
                listOf(FILE_NAME_KEY to info.getByteArray(Sodium.crypto_sign_secretkeybytes()),
                    FILE_NAME_SALT to info.getByteArray(SALT_BYTES))
            } else {
                emptyList()
            }
            val pk = info.getByteArray(Sodium.crypto_sign_publickeybytes())
            val port = info.getShort()
            val host = info.getByteArray(info.remaining()).decodeToString()

            with(preferenceManager) {
                findPreference<EditTextPreference>(SHARED_PREFERENCES_KEY_HOST)!!.text = host
                findPreference<IntEditTextPreference>(SHARED_PREFERENCES_KEY_PORT)!!.text = port.toString()
                findPreference<EditTextPreference>(SHARED_PREFERENCES_KEY_SERVER_PK)!!.text = Base64.encodeToString(pk, SERVER_PK_BASE64_FLAGS)
            }

            for ((filename, contents) in secrets) {
                context!!.openFileOutput(filename, Context.MODE_PRIVATE).use {
                    it.write(contents)
                }
            }

            Toast.makeText(context, R.string.scan_qr_done, Toast.LENGTH_LONG).show()
        } catch (e: Exception) {
            e.printStackTrace()
            Toast.makeText(context, R.string.scan_qr_error, Toast.LENGTH_LONG).show()
        }
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
    override fun persistString(value: String): Boolean = persistInt(if (value.isEmpty()) 0 else value.toInt())
}