package org.hsbp.androsphinx

import android.app.SearchManager
import android.content.Intent
import android.os.AsyncTask
import android.os.Bundle
import android.text.Editable
import android.text.InputType
import android.view.View
import android.widget.*
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.addTextChangedListener
import com.google.android.material.snackbar.Snackbar
import kotlinx.android.synthetic.main.activity_accounts.*
import kotlinx.android.synthetic.main.content_accounts.*
import java.io.IOException
import java.lang.Exception
import java.net.MalformedURLException
import java.net.URL
import java.util.*
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context

class AccountsActivity : AppCompatActivity() {

    private val cs = AndroidCredentialStore(this)

    inner class UpdateUserListTask(private val hostname: String) : AsyncTask<Void, Void, Exception?>() {

        private var users: Set<String> = emptySet()

        override fun onPreExecute() {
            pullToRefresh.isRefreshing = true
        }

        override fun doInBackground(vararg p0: Void?): Exception? {
            return try {
                users = Protocol.list(hostname, cs)
                null
            } catch (e: Exception) {
                e
            }
        }

        override fun onPostExecute(result: Exception?) {
            pullToRefresh.isRefreshing = false
            when (result) {
                null -> {
                    val objects = if (users.isEmpty()) {
                        arrayOf(UserProxy(null))
                    } else {
                        users.map(::UserProxy).toTypedArray()
                    }
                    userList.adapter =
                        ArrayAdapter<UserProxy>(this@AccountsActivity, android.R.layout.simple_list_item_1, objects)
                }
                is Protocol.ServerFailureException -> handleError(R.string.server_error_title)
                is SodiumException -> handleError(R.string.sodium_error_title)
                is IOException -> handleError(R.string.io_error_title)
                else -> handleError(R.string.unknown_error_title)
            }
        }

        private fun handleError(message: Int) {
            Snackbar.make(fab, message, Snackbar.LENGTH_LONG).setAction(R.string.retry) {
                UpdateUserListTask(hostname).execute()
            }.show()
        }
    }

    inner class GenerateTask(private val masterPassword: CharArray,
                             private val realm: Protocol.Realm,
                             private val alertDialog: AlertDialog,
                             private val feedbackLabel: TextView) : AsyncTask<Void, Void, Exception?>(), Protocol.PasswordCallback {
        private var passwordReceived: CharArray? = null

        override fun passwordReceived(password: CharArray) {
            passwordReceived = password
        }

        override fun onPreExecute() {
            feedbackLabel.setText(R.string.connecting_to_server)
        }

        override fun doInBackground(vararg p0: Void?): Exception? {
            return try {
                Protocol.get(masterPassword, realm, cs, this)
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
                        handleError(R.string.internal_error_title)
                    } else {
                        val clipboard =
                            getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        val clip = ClipData.newPlainText("password", String(pw))
                        clipboard.setPrimaryClip(clip)
                        Snackbar.make(fab, R.string.password_copied_to_clipboard, Snackbar.LENGTH_LONG).show()
                        alertDialog.dismiss()
                    }
                }
                is Protocol.ServerFailureException -> handleError(R.string.server_error_password_title)
                is SodiumException -> handleError(R.string.sodium_error_title)
                is IOException -> handleError(R.string.io_error_title)
                else -> handleError(R.string.unknown_error_title)
            }
        }

        private fun handleError(message: Int) {
            feedbackLabel.setText(message)
        }
    }

    inner class DeleteTask(private val masterPassword: CharArray,
                           private val realm: Protocol.Realm,
                           private val alertDialog: AlertDialog,
                           private val feedbackLabel: TextView) : AsyncTask<Void, Void, Exception?>() {
        override fun doInBackground(vararg p0: Void?): Exception? {
            return try {
                Protocol.delete(masterPassword, realm, cs)
                null
            } catch (e: Exception) {
                e
            }
        }

        override fun onPreExecute() {
            feedbackLabel.setText(R.string.connecting_to_server)
        }

        override fun onPostExecute(result: Exception?) {
            when (result) {
                null -> {
                    Snackbar.make(fab, R.string.user_deleted, Snackbar.LENGTH_LONG).show()
                    alertDialog.dismiss()
                    updateUserList(realm.hostname)
                }
                is Protocol.ServerFailureException -> handleError(R.string.server_error_password_title)
                is SodiumException -> handleError(R.string.sodium_error_title)
                is IOException -> handleError(R.string.io_error_title)
                else -> handleError(R.string.unknown_error_title)
            }
        }

        private fun handleError(message: Int) {
            feedbackLabel.setText(message)
        }
    }

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
                        handleError(R.string.internal_error_title)
                    } else {
                        updateUserList(realm.hostname)
                        val clipboard =
                            getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        val clip = ClipData.newPlainText("password", String(pw))
                        clipboard.setPrimaryClip(clip)
                        Snackbar.make(fab, R.string.password_copied_to_clipboard, Snackbar.LENGTH_LONG).show()
                    }
                }
                is Protocol.ServerFailureException -> handleError(R.string.server_error_title)
                is SodiumException -> handleError(R.string.sodium_error_title)
                is IOException -> handleError(R.string.io_error_title)
                else -> handleError(R.string.unknown_error_title)
            }
        }

        private fun handleError(message: Int) {
            Snackbar.make(fab, message, Snackbar.LENGTH_LONG).setAction(R.string.retry) {
                CreateTask(masterPassword, realm, charClasses, size).execute()
            }.show()
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

                if (cs.isSetUpForCommunication) {
                    updateUserList(hostname)
                } else {
                    Snackbar.make(window.decorView, R.string.no_server_setup, Snackbar.LENGTH_LONG).setAction(R.string.open_settings) {
                        startActivity(Intent(this, SettingsActivity::class.java))
                    }.show()
                    return
                }

                userList.setOnItemClickListener { adapterView, view, i, l ->
                    val username = (adapterView.getItemAtPosition(i) as UserProxy).username
                    if (username != null) showUser(Protocol.Realm(username, hostname))
                }

                fab.setOnClickListener { view ->
                    addUser(hostname, view)
                }

                pullToRefresh.setOnRefreshListener {
                    updateUserList(hostname)
                }
            }
        }
    }

    private fun addUser(hostname: String, view: View) {
        if (!cs.isSetUpForCommunication) {
            Snackbar.make(view, R.string.no_server_setup, Snackbar.LENGTH_LONG).setAction(R.string.open_settings) {
                startActivity(Intent(this, SettingsActivity::class.java))
            }.show()
            return
        }

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

    private fun showUser(realm: Protocol.Realm) {
        val linearLayout = LinearLayout(this)
        linearLayout.orientation = LinearLayout.VERTICAL

        val masterPassword = EditText(this)
        masterPassword.inputType = InputType.TYPE_TEXT_VARIATION_PASSWORD or InputType.TYPE_CLASS_TEXT
        masterPassword.setHint(R.string.master_password)
        linearLayout.addView(masterPassword)

        val feedbackLabel = TextView(this)
        linearLayout.addView(feedbackLabel)

        val btnGenerate = Button(this).apply { setText(R.string.btn_generate_copy) }
        linearLayout.addView(btnGenerate)
        val btnChange = Button(this).apply { setText(R.string.btn_generate_change) }
        linearLayout.addView(btnChange)
        val btnDelete = Button(this).apply { setText(R.string.btn_delete_user) }
        linearLayout.addView(btnDelete)

        val alertDialog = with(AlertDialog.Builder(this)) {
            setTitle(realm.username)
            setView(linearLayout)
            setNeutralButton(android.R.string.cancel, null)
        }.show()

        btnGenerate.setOnClickListener {
            GenerateTask(masterPassword.text.asCharArray, realm, alertDialog, feedbackLabel).execute()
        }

        btnChange.setOnClickListener {
            val pw = masterPassword.text.asCharArray
            // TODO ChangeTask(pw, realm).execute()
            alertDialog.dismiss()
        }

        btnDelete.setOnClickListener {
            with(AlertDialog.Builder(this)) {
                setTitle(R.string.confirm_delete_user_title)
                setMessage(getString(R.string.confirm_delete_user_msg, realm.username, realm.hostname))
                setPositiveButton(R.string.delete) { _, _ ->
                    DeleteTask(masterPassword.text.asCharArray, realm, alertDialog, feedbackLabel).execute()
                }
                setNeutralButton(R.string.keep, null)
            }.show()
        }
    }

    private fun updateUserList(hostname: String) {
        UpdateUserListTask(hostname).execute()
    }

    inner class UserProxy(val username: String?) {
        override fun toString(): String = username ?: getString(R.string.no_users_for_host)
    }
}

private val Editable.asCharArray: CharArray
    get() {
        val buf = CharArray(length)
        getChars(0, length, buf, 0)
        return buf
    }