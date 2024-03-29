// SPDX-FileCopyrightText: 2019, Andras Veres-Szentkiralyi <vsza@vsza.hu>
// SPDX-License-Identifier: MIT

package org.hsbp.androsphinx

import android.app.SearchManager
import android.content.Intent
import android.os.Bundle
import android.text.InputType
import android.view.Menu
import androidx.appcompat.app.AppCompatActivity
import android.widget.SearchView
import androidx.core.content.getSystemService
import org.hsbp.androsphinx.databinding.ActivityMainBinding
import java.net.URL

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.fabSettings.setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
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

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.menu_main, menu)

        val searchManager = getSystemService<SearchManager>()
        (menu.findItem(R.id.app_bar_search).actionView as SearchView).apply {
            setSearchableInfo(searchManager?.getSearchableInfo(componentName))
            setInputType(InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS)
        }

        return true
    }
}
