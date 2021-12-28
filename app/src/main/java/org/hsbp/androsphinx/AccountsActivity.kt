// SPDX-FileCopyrightText: 2019, Andras Veres-Szentkiralyi <vsza@vsza.hu>
// SPDX-License-Identifier: MIT


package org.hsbp.androsphinx

import android.annotation.TargetApi
import android.app.Activity
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
import com.commonsware.cwac.security.flagsecure.FlagSecureHelper
import com.google.android.material.snackbar.Snackbar
import java.io.IOException
import java.lang.Exception
import java.net.MalformedURLException
import java.net.URL
import java.util.*
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.view.autofill.AutofillManager.EXTRA_ASSIST_STRUCTURE
import android.app.assist.AssistStructure
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import android.text.format.DateUtils
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import com.nulabinc.zxcvbn.Zxcvbn
import org.hsbp.androsphinx.databinding.ActivityAccountsBinding
import kotlin.math.roundToLong

@Suppress("SpellCheckingInspection")
const val EXTRA_ACCOUNTS_AUTOFILL = "org.hsbp.androsphinx.AccountsActivity.EXTRA_ACCOUNTS_AUTOFILL"

class AccountsActivity : AppCompatActivity() {

    private val cs = AndroidCredentialStore(this)
    private var autoFill = false
    private lateinit var binding: ActivityAccountsBinding

    inner class UpdateUserListTask(private val hostname: String) : AsyncTask<Void, Void, Exception?>() {

        private var users: Set<String> = emptySet()

        override fun onPreExecute() {
            binding.accounts.pullToRefresh.isRefreshing = true
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
            binding.accounts.pullToRefresh.isRefreshing = false
            when (result) {
                null -> {
                    val objects = if (users.isEmpty()) {
                        binding.accounts.userList.announceForAccessibility(getString(R.string.no_users_for_host))
                        arrayOf(UserProxy(null))
                    } else {
                        users.map(::UserProxy).toTypedArray()
                    }
                    binding.accounts.userList.adapter =
                        ArrayAdapter(this@AccountsActivity, android.R.layout.simple_list_item_1, objects)
                }
                is Protocol.ServerFailureException -> handleError(R.string.server_error_title)
                is SodiumException -> handleError(R.string.sodium_error_title)
                is UnknownVersionException -> handleError(R.string.unknown_version_title)
                is IOException -> handleError(R.string.io_error_title)
                else -> handleError(R.string.unknown_error_title)
            }
        }

        private fun handleError(message: Int) {
            val string = getString(message)
            Snackbar.make(binding.fab, string, Snackbar.LENGTH_LONG).setAction(R.string.retry) {
                UpdateUserListTask(hostname).execute()
            }.show()
            binding.fab.announceForAccessibility(string)
        }
    }

    abstract inner class UserTask(private val feedbackLabel: TextView) : AsyncTask<Void, Void, Exception?>(), Protocol.PasswordCallback {
        private var passwordReceived: CharArray? = null

        override fun passwordReceived(password: CharArray) {
            passwordReceived = password
        }

        override fun ruleReceived(rule: Rule) {}

        fun updateLabel(message: Int) {
            val string = getString(message)
            feedbackLabel.text = string
            feedbackLabel.announceForAccessibility(string)
        }

        override fun onPreExecute() {
            updateLabel(R.string.connecting_to_server)
        }

        override fun doInBackground(vararg p0: Void?): Exception? {
            return try {
                run()
                null
            } catch (e: Exception) {
                e
            }
        }

        abstract fun run()
        abstract fun handlePassword(pw: CharArray)

        override fun onPostExecute(result: Exception?) {
            when (result) {
                null -> {
                    val pw = passwordReceived
                    if (pw == null) {
                        handleError(R.string.internal_error_title)
                    } else {
                        handlePassword(pw)
                    }
                }
                is Protocol.ServerFailureException -> handleError(R.string.server_error_password_title)
                is SodiumException -> handleError(R.string.sodium_error_title)
                is Protocol.CheckDigitMismatchException -> handleError(R.string.check_digit_mismatch_title)
                is UnknownVersionException -> handleError(R.string.unknown_version_title)
                is IOException -> handleError(R.string.io_error_title)
                else -> handleError(R.string.unknown_error_title)
            }
        }

        private fun handleError(message: Int) = updateLabel(message)

        fun showSnackbar(message: Int) {
            val msg = getString(message)
            Snackbar.make(binding.fab, msg, Snackbar.LENGTH_LONG).show()
            binding.fab.announceForAccessibility(msg)
        }
    }

    @TargetApi(26)
    inner class AutoFillTask(masterPassword: CharArray,
                             private val realm: Protocol.Realm,
                             private val alertDialog: AlertDialog,
                             feedbackLabel: TextView) : GenerateTask(masterPassword, realm, alertDialog, feedbackLabel) {
        override fun handlePassword(pw: CharArray) {
            val structure: AssistStructure = intent.getParcelableExtra(EXTRA_ASSIST_STRUCTURE)!!
            val result = SphinxAutofillService.ParseResult()
            SphinxAutofillService.parse(structure.getWindowNodeAt(0).rootViewNode, result)
            val remoteView =
                RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
                    setTextViewText(android.R.id.text1, getString(R.string.autofill_remote_button_user_text, realm.username))
                }
            val b = Dataset.Builder(remoteView)
            result.usernames.filterNotNull().forEach { b.setValue(it, AutofillValue.forText(realm.username)) }
            result.passwords.filterNotNull().forEach { b.setValue(it, AutofillValue.forText(String(pw))) }
            val fr = FillResponse.Builder().addDataset(b.build()).build()
            val reply = Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, fr)
            setResult(Activity.RESULT_OK, reply)
            alertDialog.dismiss() // if we don't close it explicitly, an exception is thrown for leaking it
            finish()
        }
    }

    open inner class GenerateTask(private val masterPassword: CharArray,
                             private val realm: Protocol.Realm,
                             private val alertDialog: AlertDialog,
                             feedbackLabel: TextView) : UserTask(feedbackLabel) {

        override fun run() = Protocol.get(masterPassword, realm, cs, this)

        override fun handlePassword(pw: CharArray) {
            copyPasswordToClipboard(pw)
            showSnackbar(R.string.password_copied_to_clipboard)
            alertDialog.dismiss()
        }
    }

    inner class ChangeTask(private val masterPassword: CharArray,
                           private val realm: Protocol.Realm,
                           feedbackLabel: TextView) : CopyUpdateTask(feedbackLabel, R.string.password_change_mode) {

        private var rule: Rule? = null

        override fun run() {
            val masterPasswordClone = masterPassword.clone()
            Protocol.get(masterPassword, realm, cs, this)
            val r = rule ?: throw Protocol.ServerFailureException()
            Protocol.change(masterPasswordClone, realm, r.charClasses, cs, this, r.symbols, r.size.toInt())
        }

        override fun ruleReceived(rule: Rule) {
            this.rule = rule
        }
    }

    inner class UndoTask(private val masterPassword: CharArray,
                           private val realm: Protocol.Realm,
                           feedbackLabel: TextView) : CopyUpdateTask(feedbackLabel, R.string.old_password_copied_to_clipboard) {

        override fun run() = Protocol.undo(masterPassword, realm, cs)
    }

    inner class CommitTask(private val masterPassword: CharArray,
                           private val realm: Protocol.Realm,
                           feedbackLabel: TextView) : CopyUpdateTask(feedbackLabel, R.string.new_password_copied_to_clipboard) {

        override fun run() = Protocol.commit(masterPassword, realm, cs)
    }

    abstract inner class CopyUpdateTask(feedbackLabel: TextView,
                                        private val successMessage: Int) : UserTask(feedbackLabel) {
        override fun handlePassword(pw: CharArray) {
            copyPasswordToClipboard(pw)
            updateLabel(successMessage)
        }
    }

    private fun copyPasswordToClipboard(pw: CharArray) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("password", String(pw))
        clipboard.setPrimaryClip(clip)
    }

    inner class DeleteTask(private val masterPassword: CharArray,
                           private val realm: Protocol.Realm,
                           private val alertDialog: AlertDialog,
                           feedbackLabel: TextView) : UserTask(feedbackLabel) {

        override fun run() {
            Protocol.delete(masterPassword, realm, cs)
        }

        override fun handlePassword(pw: CharArray) {
            showSnackbar(R.string.user_deleted)
            alertDialog.dismiss()
            updateUserList(realm.hostname)
        }
    }

    inner class CreateTask(private val masterPassword: CharArray, private val realm: Protocol.Realm,
                     private val charClasses: Set<CharacterClass>,
                     private val size: Int) : AsyncTask<Void, Void, Exception?>(), Protocol.PasswordCallback {

        private var passwordReceived: CharArray? = null

        override fun passwordReceived(password: CharArray) {
            passwordReceived = password
        }

        override fun ruleReceived(rule: Rule) {}

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
                        copyPasswordToClipboard(pw)
                        Snackbar.make(binding.fab, R.string.password_copied_to_clipboard, Snackbar.LENGTH_LONG).show()
                    }
                }
                is Protocol.ServerFailureException -> handleError(R.string.server_error_title)
                is SodiumException -> handleError(R.string.sodium_error_title)
                is UnknownVersionException -> handleError(R.string.unknown_version_title) // beacuse of user list update
                is IOException -> handleError(R.string.io_error_title)
                else -> handleError(R.string.unknown_error_title)
            }
        }

        private fun handleError(message: Int) {
            Snackbar.make(binding.fab, message, Snackbar.LENGTH_LONG).setAction(R.string.retry) {
                CreateTask(masterPassword, realm, charClasses, size).execute()
            }.show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityAccountsBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)

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

                binding.accounts.userList.setOnItemClickListener { adapterView, _, i, _ ->
                    val username = (adapterView.getItemAtPosition(i) as UserProxy).username
                    if (username != null) showUser(Protocol.Realm(username, hostname))
                }

                binding.fab.setOnClickListener { view ->
                    addUser(hostname, view)
                }

                binding.accounts.pullToRefresh.setOnRefreshListener {
                    updateUserList(hostname)
                }

                autoFill = intent.hasExtra(EXTRA_ACCOUNTS_AUTOFILL)
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
                cb.setText(cc.description)
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
        val passwordStrengthMeter = TextView(this)
        linearLayout.addView(passwordStrengthMeter)

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
        }.create()

        FlagSecureHelper.markDialogAsSecure(alertDialog).show()
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

        val zxcvbn = Zxcvbn()
        val strengthLevels = arrayOf(R.string.password_strength_weak, R.string.password_strength_fair,
            R.string.password_strength_good, R.string.password_strength_strong, R.string.password_strength_very_strong)

        masterPasswords[0].addTextChangedListener { field: Editable? ->
            val strength = zxcvbn.measure(field ?: return@addTextChangedListener)
            val cts = strength.crackTimeSeconds
            val now = Date().time
            val cracked = now + (cts.onlineThrottling100perHour * 1000).roundToLong()
            passwordStrengthMeter.text = getString(R.string.password_strength_format,
                getString(strengthLevels[strength.score]),
                DateUtils.getRelativeTimeSpanString(cracked, now, 0L))
        }

        ccWidgets.values.forEach {
            it.setOnCheckedChangeListener { _, _ ->
                updateEnabled()
            }
        }

        updateEnabled()
    }

    private fun showUser(realm: Protocol.Realm, feedbackText: Int? = null) {
        val linearLayout = LinearLayout(this)
        linearLayout.orientation = LinearLayout.VERTICAL

        val masterPassword = EditText(this)
        masterPassword.inputType = InputType.TYPE_TEXT_VARIATION_PASSWORD or InputType.TYPE_CLASS_TEXT
        masterPassword.setHint(R.string.master_password)
        linearLayout.addView(masterPassword)

        val feedbackLabel = TextView(this)
        if (feedbackText != null) feedbackLabel.setText(feedbackText)
        linearLayout.addView(feedbackLabel)

        val btnAutoFill = Button(this).apply { setText(R.string.btn_generate_autofill) }
        val btnGenerate = Button(this).apply { setText(R.string.btn_generate_copy) }
        val btnChange = Button(this).apply { setText(R.string.btn_generate_change) }
        val btnUndo = Button(this).apply { setText(R.string.btn_undo_change) }
        val btnCommit = Button(this).apply { setText(R.string.btn_commit_change) }
        val btnDelete = Button(this).apply { setText(R.string.btn_delete_user) }

        if (autoFill) linearLayout.addView(btnAutoFill)
        linearLayout.addView(btnGenerate)
        linearLayout.addView(btnChange)
        linearLayout.addView(btnCommit)
        linearLayout.addView(btnUndo)
        linearLayout.addView(btnDelete)

        val alertDialog = with(AlertDialog.Builder(this)) {
            setTitle(realm.username)
            setView(linearLayout)
            setNeutralButton(R.string.close, null)
            create()
        }
        FlagSecureHelper.markDialogAsSecure(alertDialog).show()

        if (autoFill) btnAutoFill.setOnClickListener {
            AutoFillTask(masterPassword.text.asCharArray, realm, alertDialog, feedbackLabel).execute()
        }

        btnGenerate.setOnClickListener {
            GenerateTask(masterPassword.text.asCharArray, realm, alertDialog, feedbackLabel).execute()
        }

        btnChange.setOnClickListener {
            ChangeTask(masterPassword.text.asCharArray, realm, feedbackLabel).execute()
        }

        btnUndo.setOnClickListener {
            UndoTask(masterPassword.text.asCharArray, realm, feedbackLabel).execute()
        }

        btnCommit.setOnClickListener {
            CommitTask(masterPassword.text.asCharArray, realm, feedbackLabel).execute()
        }

        btnDelete.setOnClickListener {
            with(AlertDialog.Builder(this)) {
                setTitle(R.string.confirm_delete_user_title)
                setMessage(getString(R.string.confirm_delete_user_msg, realm.username, realm.hostname))
                setPositiveButton(R.string.delete) { _, _ ->
                    DeleteTask(masterPassword.text.asCharArray, realm, alertDialog, feedbackLabel).execute()
                }
                setNeutralButton(R.string.keep, null)
                show()
            }
        }
    }

    private fun updateUserList(hostname: String) {
        UpdateUserListTask(hostname).execute()
    }

    inner class UserProxy(val username: String?) {
        override fun toString(): String =
            if (username == null) getString(R.string.no_users_for_host)
            else "\uD83D\uDC64  $username"
    }
}

private val Editable.asCharArray: CharArray
    get() {
        val buf = CharArray(length)
        getChars(0, length, buf, 0)
        return buf
    }
