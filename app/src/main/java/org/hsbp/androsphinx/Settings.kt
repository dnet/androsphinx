// SPDX-FileCopyrightText: 2019, Andras Veres-Szentkiralyi <vsza@vsza.hu>
// SPDX-License-Identifier: MIT

package org.hsbp.androsphinx

import android.annotation.TargetApi
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Point
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.text.InputType
import android.util.AttributeSet
import android.view.View
import android.view.autofill.AutofillManager
import android.widget.ImageView
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.getSystemService
import androidx.core.graphics.Insets
import androidx.core.graphics.createBitmap
import androidx.core.graphics.drawable.toDrawable
import androidx.core.net.toUri
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.preference.EditTextPreference
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import com.commonsware.cwac.security.flagsecure.FlagSecureHelper
import com.google.android.material.snackbar.Snackbar
import com.google.zxingsphinx.zxing.BarcodeFormat
import com.google.zxingsphinx.zxing.qrcode.QRCodeWriter
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions

class SettingsActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)
        supportFragmentManager
            .beginTransaction()
            .replace(R.id.settings_container, SettingsFragment())
            .commit()

        if (Build.VERSION.SDK_INT >= 35) {
            ViewCompat.setOnApplyWindowInsetsListener(
                findViewById(R.id.settings_container)
            ) { v: View, insets: WindowInsetsCompat ->
                val systemBars: Insets = insets.getInsets(WindowInsetsCompat.Type.systemBars())
                v.setPadding(0, systemBars.top, 0, 0)
                insets
            }
        }
    }
}

const val BLACK: Int = 0xFF000000.toInt()
const val WHITE: Int = 0xFFFFFFFF.toInt()

class SettingsFragment : PreferenceFragmentCompat(), Preference.OnPreferenceClickListener {
    private val openAutoFillSettings = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        updateAutoFillStatus()
    }

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        setPreferencesFromResource(R.xml.preferences, rootKey)
        preferenceManager.findPreference<Preference>("scan_qr")!!.onPreferenceClickListener = this
        ShareType.entries.forEach { t ->
            val p = preferenceManager.findPreference<Preference>(t.key)!!
            p.setOnPreferenceClickListener {
                showQR(t.serialize(requireContext()), p.title, t == ShareType.PRIVATE)
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
                        pref.summary = ""
                    } else {
                        pref.isEnabled = true
                        pref.setTitle(R.string.request_autofill_set_title)
                        pref.setSummary(R.string.request_autofill_set_summary)
                        pref.setOnPreferenceClickListener {
                            openAutoFillSettings.launch(
                                Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE).setData(
                                    "package:${ctx.packageName}".toUri()
                                )
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

    private fun showQR(payload: ByteArray, title: CharSequence?, hasSecret: Boolean) {
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
        val bm = createBitmap(w, h)
        bm.setPixels(pixels, 0, w, 0, 0, w, h)
        with(AlertDialog.Builder(requireContext())) {
            setTitle(title)
            setView(ImageView(context).apply {
                setImageDrawable(bm.toDrawable(requireActivity().resources))
            })
            setNeutralButton(R.string.close, null)
            if (hasSecret) FlagSecureHelper.markDialogAsSecure(create()).show() else show()
        }
    }

    override fun onPreferenceClick(preference: Preference): Boolean {
        initiateScan()
        return true
    }

    private fun initiateScan() {
        val options = ScanOptions()
        options.setDesiredBarcodeFormats(ScanOptions.QR_CODE)
        barcodeLauncher.launch(options)
    }

    private val barcodeLauncher: ActivityResultLauncher<ScanOptions> = registerForActivityResult(
        ScanContract()) { result ->
            val rb = result.rawBytes
            if (rb == null) return@registerForActivityResult
            try {
                val parsed = SerializedCredentialStore.fromQrRawBytes(rb)

                if (parsed.hasKey) {
                    val ctx = requireContext()
                    val cs = AndroidCredentialStore(ctx)
                    if (cs.configFileExists && !cs.key.contentEquals(parsed.key)) {
                        with(AlertDialog.Builder(ctx)) {
                            setTitle(R.string.master_key_overwrite_title)
                            setMessage(R.string.master_key_overwrite_msg)
                            setNegativeButton(R.string.keep, null)
                            setPositiveButton(R.string.overwrite) { _, _ ->
                                cs.updateSettings(parsed)
                            }
                            show()
                        }
                    } else {
                        cs.updateSettings(parsed)
                    }
                }

                Snackbar.make(requireView(), R.string.scan_qr_done, Snackbar.LENGTH_LONG).show()
            } catch (e: Exception) {
                e.printStackTrace()
                Snackbar.make(requireView(), R.string.scan_qr_error,
                    Snackbar.LENGTH_LONG).setAction(R.string.retry) { initiateScan() }.show()
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
    override fun persistString(value: String): Boolean = persistInt(value.toIntOrNull() ?: 0)
}
