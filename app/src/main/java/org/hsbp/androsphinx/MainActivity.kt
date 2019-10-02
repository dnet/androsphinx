package org.hsbp.androsphinx

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import kotlinx.android.synthetic.main.activity_main.*
import org.libsodium.jni.NaCl

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        NaCl.sodium()

        Sphinx.Challenge("shitty password\u0000".toCharArray()).use { c ->
            val secret = ByteArray(32) { ' '.toByte() }
            val resp = Sphinx.respond(c.challenge, secret)
            val rwd = c.finish(resp)
            output.text = rwd.joinToString { it.toString(16).padStart(2, '0') }
        }

        button.setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }
    }
}
