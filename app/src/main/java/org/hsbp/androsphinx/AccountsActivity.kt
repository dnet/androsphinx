package org.hsbp.androsphinx

import android.app.SearchManager
import android.content.Intent
import android.os.AsyncTask
import android.os.Bundle
import android.text.Editable
import android.text.InputType
import android.widget.*
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.addTextChangedListener
import kotlinx.android.synthetic.main.activity_accounts.*
import kotlinx.android.synthetic.main.content_accounts.*
import java.lang.Exception
import java.net.MalformedURLException
import java.net.URL
import java.util.*

class AccountsActivity : AppCompatActivity() {

    private val cs = AndroidCredentialStore(this)

    inner class CreateTask(private val masterPassword: CharArray, private val realm: Protocol.Realm,
                     private val charClasses: Set<CharacterClass>,
                     private val size: Int) : AsyncTask<Void, Void, Exception?>(), Protocol.PasswordCallback {

        private var passwordReceived: CharArray? = null

        override fun passwordReceived(password: CharArray) {
            passwordReceived = password
        }

        override fun doInBackground(vararg p0: Void?): Exception? {
            return try {
                Protocol.create(masterPassword, realm, charClasses, cs, this, size)
                null
            } catch (e: Exception) {
                e
            }
        }

        override fun onPostExecute(result: Exception?) {
            when (result) {
                null -> {
                    val pw = passwordReceived
                    if (pw == null) {
                        // TODO
                        println("wtf")
                    } else {
                        // TODO success
                        println(String(pw))
                        updateUserList(realm.hostname)
                    }
                }
                is Protocol.ServerFailureException -> {
                    // TODO
                    println(getString(R.string.server_error_title))
                }
                // TODO handle more exceptions like cryptography and networking
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_accounts)
        setSupportActionBar(toolbar)

        if (Intent.ACTION_SEARCH == intent.action) {
            intent.getStringExtra(SearchManager.QUERY)?.also { query ->
                val hostname = try {
                    URL(query).host
                } catch (e: MalformedURLException) {
                    query
                }
                title = hostname

                updateUserList(hostname)

                fab.setOnClickListener {
                    addUser(hostname)
                }
            }
        }
    }

    private fun addUser(hostname: String) {
        // TODO check for settings validity before showing UI

        val linearLayout = LinearLayout(this)
        linearLayout.orientation = LinearLayout.VERTICAL
        val username = EditText(this)
        username.inputType =
            InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
        username.setHint(R.string.add_username_placeholder)
        linearLayout.addView(username)
        val passwordLength = EditText(this)
        passwordLength.setHint(R.string.add_password_length_placeholder)
        passwordLength.inputType = InputType.TYPE_CLASS_NUMBER
        linearLayout.addView(passwordLength)
        val ccWidgets =
            CharacterClass.values().asIterable().associateWithTo(EnumMap(CharacterClass::class.java)) { cc ->
                val cb = CheckBox(this)
                cb.text = cc.name.toLowerCase(Locale.ROOT)
                cb.isChecked = true
                linearLayout.addView(cb)
                cb
            } as Map<CharacterClass, CheckBox>
        val masterPasswords =
            arrayOf(R.string.master_password, R.string.master_password_confirm).map { hint ->
                val et = EditText(this)
                et.inputType = InputType.TYPE_TEXT_VARIATION_PASSWORD or InputType.TYPE_CLASS_TEXT
                et.setHint(hint)
                linearLayout.addView(et)
                et
            }

        val alertDialog = with(AlertDialog.Builder(this)) {
            setTitle(R.string.add_username_title)
            setView(linearLayout)
            setPositiveButton(R.string.add_username_btn) { _, _ ->
                val rule = ccWidgets.filterValues(CheckBox::isChecked).keys
                val size = passwordLength.text.toString().toIntOrNull() ?: 0
                val realm = Protocol.Realm(username.text.toString(), hostname)
                val pw = masterPasswords[0].text.asCharArray
                masterPasswords.forEach { it.text.clear() }
                CreateTask(pw, realm, rule, size).execute()
            }
            setNeutralButton(android.R.string.cancel, null)
        }.show()

        val btn = alertDialog.getButton(AlertDialog.BUTTON_POSITIVE)

        fun updateEnabled() {
            btn.isEnabled =
                username.text.isNotEmpty() and ccWidgets.values.any(CheckBox::isChecked) and
                        masterPasswords[0].text.asCharArray.contentEquals(masterPasswords[1].text.asCharArray) and masterPasswords[0].text.isNotEmpty()
        }

        sequence { yield(username); yieldAll(masterPasswords); }.forEach {
            it.addTextChangedListener {
                updateEnabled()
            }
        }

        ccWidgets.values.forEach {
            it.setOnCheckedChangeListener { _, _ ->
                updateEnabled()
            }
        }

        updateEnabled()
    }

    private fun updateUserList(hostname: String) {
        val users = Protocol.list(hostname, cs)
        val objects = if (users.isEmpty()) {
            arrayOf(UserProxy(null))
        } else {
            users.map(::UserProxy).toTypedArray()
        }
        userList.adapter =
            ArrayAdapter<UserProxy>(this, android.R.layout.simple_list_item_1, objects)
    }

    inner class UserProxy(private val username: String?) {
        override fun toString(): String = username ?: getString(R.string.no_users_for_host)
    }
}

private val Editable.asCharArray: CharArray
    get() {
        val buf = CharArray(length)
        getChars(0, length, buf, 0)
        return buf
    }