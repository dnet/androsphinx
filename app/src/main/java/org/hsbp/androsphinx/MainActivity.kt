package org.hsbp.androsphinx

import android.app.SearchManager
import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import kotlinx.android.synthetic.main.activity_main.*
import java.net.URL

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        button.setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }

        search_btn.setOnClickListener {
            onSearchRequested()
        }

        val i = intent
        if (i.action == Intent.ACTION_SEND && i.type == "text/plain") {
            val sharedText = i.getStringExtra(Intent.EXTRA_TEXT) ?: return
            val url = try {
                URL(sharedText)
            } catch (e: Exception) {
                return
            }
            startActivity(with(Intent(this, AccountsActivity::class.java)) {
                action = Intent.ACTION_SEARCH
                putExtra(SearchManager.QUERY, url.toString())
            })
        }
    }
}
