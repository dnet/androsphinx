package org.hsbp.androsphinx

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import kotlinx.android.synthetic.main.activity_main.output
import org.libsodium.jni.NaCl

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
    }
}
