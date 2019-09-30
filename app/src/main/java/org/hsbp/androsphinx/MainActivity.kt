package org.hsbp.androsphinx

import android.annotation.SuppressLint
import android.content.Intent
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.Toast
import com.google.zxing.integration.android.IntentIntegrator
import kotlinx.android.synthetic.main.activity_main.*
import org.libsodium.jni.NaCl
import org.libsodium.jni.Sodium

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        NaCl.sodium()

        val c = Sphinx.Challenge("shitty password\u0000".toCharArray())
        val secret = ByteArray(32) { ' '.toByte() }
        val resp = Sphinx.respond(c.challenge, secret)
        val rwd = c.finish(resp)
        output.text = rwd.joinToString { it.toString(16).padStart(2, '0') }

        button.setOnClickListener {
            IntentIntegrator(this).initiateScan()
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

            storeServerInfo(host, port, pk)

            Toast.makeText(this, R.string.scan_qr_done, Toast.LENGTH_LONG).show()
        } catch (e: Exception) {
            e.printStackTrace()
            Toast.makeText(this, R.string.scan_qr_error, Toast.LENGTH_LONG).show()
        }
    }
}
