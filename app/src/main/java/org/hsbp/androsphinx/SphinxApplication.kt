// SPDX-FileCopyrightText: 2019, Andras Veres-Szentkiaalyi <vsza@vsza.hu>
// SPDX-License-Identifier: MIT

package org.hsbp.androsphinx

import android.app.Application
import org.libsodium.jni.NaCl

@Suppress("UNUSED")
class SphinxApplication : Application() {
    init {
        NaCl.sodium()
    }
}
