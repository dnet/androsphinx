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
        val info = ir.byteSegments0

        try {
            val pkBytes = Sodium.crypto_sign_publickeybytes()
            val pk = info.sliceArray(0 until pkBytes)
            val port = (info[pkBytes].toInt() shl 8) or info[pkBytes + 1].toInt()
            val host = info.decodeToString(startIndex = pkBytes + 2)

            with(preferenceManager) {
                findPreference<EditTextPreference>(SHARED_PREFERENCES_KEY_HOST)!!.text = host
                findPreference<IntEditTextPreference>(SHARED_PREFERENCES_KEY_PORT)!!.text = port.toString()
                findPreference<EditTextPreference>(SHARED_PREFERENCES_KEY_SERVER_PK)!!.text = Base64.encodeToString(pk, SERVER_PK_BASE64_FLAGS)
            }

            Toast.makeText(context, R.string.scan_qr_done, Toast.LENGTH_LONG).show()
        } catch (e: Exception) {
            e.printStackTrace()
            Toast.makeText(context, R.string.scan_qr_error, Toast.LENGTH_LONG).show()
        }
    }
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