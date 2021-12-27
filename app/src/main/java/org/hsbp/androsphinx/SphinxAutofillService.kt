// SPDX-FileCopyrightText: 2019, Andras Veres-Szentkiralyi <vsza@vsza.hu>
// SPDX-License-Identifier: MIT

package org.hsbp.androsphinx

import android.annotation.TargetApi
import android.app.PendingIntent
import android.app.SearchManager
import android.app.assist.AssistStructure
import android.content.Intent
import android.os.CancellationSignal
import android.service.autofill.*
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import java.util.*
import kotlin.collections.HashSet

@TargetApi(26)
class SphinxAutofillService : AutofillService() {

    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal,
                               callback: FillCallback) {

        val structure = request.fillContexts.last().structure
        val rvn = structure.getWindowNodeAt(0).rootViewNode

        val result = ParseResult()
        parse(rvn, result)
        val domain = result.domains.firstOrNull(String::isNotEmpty)
        if (domain == null) {
            callback.onFailure(getString(R.string.autofill_no_domain_failure))
        } else {
            val ids = (result.usernames union result.passwords).toTypedArray()
            if (ids.isEmpty()) {
                callback.onFailure(getString(R.string.autofill_no_inputs))
                return
            }
            val authIntent = Intent(this, AccountsActivity::class.java).apply {
                action = Intent.ACTION_SEARCH
                putExtra(EXTRA_ACCOUNTS_AUTOFILL, true)
                putExtra(SearchManager.QUERY, domain)
            }
            val authentication = PendingIntent.getActivity(this, 1001, authIntent, PendingIntent.FLAG_CANCEL_CURRENT).intentSender
            val presentation =  RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
                setTextViewText(android.R.id.text1, getString(R.string.autofill_remote_button_text))
            }
            val fr = FillResponse.Builder().setAuthentication(ids, authentication, presentation).build()
            callback.onSuccess(fr)
        }
    }

    class ParseResult(val domains: MutableSet<String> = HashSet(), val usernames: MutableSet<AutofillId?> = HashSet(),
                      val passwords: MutableSet<AutofillId?> = HashSet())

    companion object {
        fun parse(node: AssistStructure.ViewNode, result: ParseResult) {
            val wd = node.webDomain
            if (wd != null) result.domains.add(wd)

            val hints = node.autofillHints ?: inferHints(node.idEntry)

            val target = if (hints == null) {
                if (node.autofillType == View.AUTOFILL_TYPE_TEXT && (node.inputType and InputType.TYPE_CLASS_TEXT) != 0) {
                    when (node.inputType and InputType.TYPE_CLASS_TEXT.inv()) {
                        InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS ->
                            result.usernames
                        InputType.TYPE_TEXT_VARIATION_PASSWORD,
                        InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD ->
                            result.passwords
                        else -> null
                    }
                } else null
            } else {
                when {
                    View.AUTOFILL_HINT_USERNAME in hints ||
                            View.AUTOFILL_HINT_EMAIL_ADDRESS in hints -> result.usernames
                    View.AUTOFILL_HINT_PASSWORD in hints -> result.passwords
                    else -> null
                }
            }

            target?.add(node.autofillId)

            for (i in 0 until node.childCount) {
                parse(node.getChildAt(i), result)
            }
        }

        private fun inferHints(idEntry: String?): Array<String>? {
            val hint = idEntry?.lowercase(Locale.ROOT)
            if (hint == null || "label" in hint || "container" in hint) return null

            if ("password" in hint) return arrayOf(View.AUTOFILL_HINT_PASSWORD)
            if ("username" in hint || ("login" in hint && "id" in hint)) return arrayOf(View.AUTOFILL_HINT_USERNAME)
            if ("email" in hint) return arrayOf(View.AUTOFILL_HINT_EMAIL_ADDRESS)
            if ("name" in hint) return arrayOf(View.AUTOFILL_HINT_NAME)
            if ("phone" in hint) return arrayOf(View.AUTOFILL_HINT_PHONE)
            return null
        }
    }

    override fun onSaveRequest(_request: SaveRequest, callback: SaveCallback) {
        callback.onFailure(getString(R.string.on_save_request_message))
    }
}
