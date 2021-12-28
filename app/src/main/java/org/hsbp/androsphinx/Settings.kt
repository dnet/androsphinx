// SPDX-FileCopyrightText: 2019, Andras Veres-Szentkiralyi <vsza@vsza.hu>
// SPDX-License-Identifier: MIT

package org.hsbp.androsphinx

import android.annotation.SuppressLint
import android.annotation.TargetApi
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.text.InputType
import android.util.AttributeSet
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.preference.EditTextPreference
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import com.google.zxing.integration.android.IntentIntegrator
import java.nio.ByteBuffer
import java.nio.ByteOrder
import android.graphics.Bitmap
import android.graphics.Point
import android.graphics.drawable.BitmapDrawable
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.view.autofill.AutofillManager
import android.widget.ImageView
import androidx.appcompat.app.AlertDialog
import androidx.core.content.getSystemService
import androidx.preference.SwitchPreference
import com.commonsware.cwac.security.flagsecure.FlagSecureHelper
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import java.util.*

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
const val QR_FLAGS_RWD_KEYS: Int = 2
const val BLACK: Int = 0xFF000000.toInt()
const val WHITE: Int = 0xFFFFFFFF.toInt()

const val REQUEST_SET_AUTO_FILL_SERVICE: Int = 1

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
                showQR(t.serialize(requireContext()), p.title, t.privateMaterialSize > 0)
                true
            }
        }
        updateAutoFillStatus()
    }

    @TargetApi(26)
    private fun updateAutoFillStatus() {
        val pref = preferenceManager.findPreference<Preference>("auto_fill_status")!!
        val ctx = requireContext()
        if (Build.VERSION.SDK_INT >= 26 && ctx.packageManager.hasSystemFeature(PackageManager.FEATURE_AUTOFILL)) {
            val afm = ctx.getSystemService<AutofillManager>()
            if (afm == null) {
                pref.isEnabled = false
                pref.setTitle(R.string.autofill_system_service_null_title)
                pref.setSummary(R.string.autofill_system_service_null_summary)
            } else {
                if (afm.isAutofillSupported) {
                    if (afm.hasEnabledAutofillServices()) {
                        pref.isEnabled = false
                        pref.setTitle(R.string.autofill_provider_already_set)
                    } else {
                        pref.isEnabled = true
                        pref.setTitle(R.string.request_autofill_set_title)
                        pref.setSummary(R.string.request_autofill_set_summary)
                        pref.setOnPreferenceClickListener {
                            startActivityForResult(
                                Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE).setData(
                                    Uri.parse("package:${ctx.packageName}")
                                ), REQUEST_SET_AUTO_FILL_SERVICE
                            )
                            true
                        }
                    }
                } else {
                    pref.isEnabled = false
                    pref.setTitle(R.string.autofill_not_supported_title)
                    pref.setSummary(R.string.autofill_not_supported_summary)
                }
            }
        } else {
            pref.isEnabled = false
            pref.setTitle(R.string.autofill_no_os_feature_title)
            pref.setSummary(R.string.autofill_no_os_feature_summary)
        }
    }

    private fun showQR(payload: ByteArray, title: CharSequence, hasSecret: Boolean) {
        val (width, height) = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val bounds = requireActivity().windowManager.currentWindowMetrics.bounds
            bounds.width() to bounds.height()
        } else {
            val display = requireActivity().windowManager.defaultDisplay
            val size = Point()
            display.getSize(size)
            size.x to size.y
        }
        val dimension = width.coerceAtMost(height) / 4 * 3
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
            setNeutralButton(R.string.close, null)
            if (hasSecret) FlagSecureHelper.markDialogAsSecure(create()).show() else show()
        }
    }

    @Suppress("UsePropertyAccessSyntax")
    @SuppressLint("MissingSuperCall")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == IntentIntegrator.REQUEST_CODE) {
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
                val rwdKeys = (formatFlags and QR_FLAGS_RWD_KEYS) == QR_FLAGS_RWD_KEYS

                with(preferenceManager) {
                    findPreference<EditTextPreference>(SHARED_PREFERENCES_KEY_HOST)!!.text = host
                    findPreference<IntEditTextPreference>(SHARED_PREFERENCES_KEY_PORT)!!.text =
                        port.toString()
                    findPreference<SwitchPreference>(SHARED_PREFERENCES_KEY_RWD_KEYS)!!.isChecked = rwdKeys
                }

                if (masterKey != null) {
                    val ctx = requireContext()
                    val cs = AndroidCredentialStore(ctx)
                    if (cs.keyFileExists && !cs.key.contentEquals(masterKey)) {
                        with(AlertDialog.Builder(ctx)) {
                            setTitle(R.string.master_key_overwrite_title)
                            setMessage(R.string.master_key_overwrite_msg)
                            setNegativeButton(R.string.keep, null)
                            setPositiveButton(R.string.overwrite) { _, _ ->
                                cs.writeMasterKey(masterKey)
                            }
                            show()
                        }
                    } else {
                        cs.writeMasterKey(masterKey)
                    }
                }

                Toast.makeText(context, R.string.scan_qr_done, Toast.LENGTH_LONG).show()
            } catch (e: Exception) {
                e.printStackTrace()
                Toast.makeText(context, R.string.scan_qr_error, Toast.LENGTH_LONG).show()
            }
        } else if (requestCode == REQUEST_SET_AUTO_FILL_SERVICE) {
            updateAutoFillStatus()
        }
    }
}

enum class ShareType(private val code: Byte) {
    @Suppress("UNUSED") PUBLIC(code = 0),
    @Suppress("UNUSED") PRIVATE(code = QR_FLAGS_HAS_KEY.toByte()) {
        override val privateMaterialSize: Int
            get() = MASTER_KEY_BYTES

        override fun providePrivateMaterial(target: ByteBuffer, cs: Protocol.CredentialStore) {
            target.put(cs.key.asBytes)
        }
    };

    open fun providePrivateMaterial(target: ByteBuffer, cs: Protocol.CredentialStore) {}
    open val privateMaterialSize: Int
        get() = 0

    val key: String
        get() = "share_qr_${name.lowercase(Locale.ROOT)}"

    fun serialize(context: Context): ByteArray {
        val cs = AndroidCredentialStore(context)
        val hostBytes = cs.host.toByteArray()
        val info = ByteBuffer.allocate(1 + 2 + hostBytes.size + privateMaterialSize)

        with(info) {
            put(if (cs.rwdKeys) (code.toInt() or QR_FLAGS_RWD_KEYS).toByte() else code)
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
