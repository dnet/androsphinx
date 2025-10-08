// SPDX-FileCopyrightText: 2019, Andras Veres-Szentkiralyi <vsza@vsza.hu>
// SPDX-License-Identifier: MIT

package org.hsbp.androsphinx

import android.app.Application

@Suppress("UNUSED")
class SphinxApplication : Application() {
    init {
        System.loadLibrary("equihash") // and transitively, (lib)sodium
        System.loadLibrary("oprf") // and transitively, (lib)sodium and (lib)oprf-noiseXK
    }
}
