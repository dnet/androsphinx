package org.hsbp.androsphinx

import android.os.CancellationSignal
import android.service.autofill.*

class SphinxAutofillService : AutofillService() {
    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal,
                               callback: FillCallback) {

        // TODO
    }

    override fun onSaveRequest(_request: SaveRequest, callback: SaveCallback) {
        callback.onFailure(getString(R.string.on_save_request_message))
    }
}
