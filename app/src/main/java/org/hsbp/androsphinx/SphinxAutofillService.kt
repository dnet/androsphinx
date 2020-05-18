package org.hsbp.androsphinx

import android.os.CancellationSignal
import android.service.autofill.*

class SphinxAutofillService : AutofillService() {
    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal,
                               callback: FillCallback) {

        // TODO
    }

    override fun onSaveRequest(p0: SaveRequest, p1: SaveCallback) {
        // TODO
    }
}
