package org.hsbp.androsphinx

import android.app.Application
import org.libsodium.jni.NaCl

@Suppress("UNUSED")
class SphinxApplication : Application() {
    init {
        NaCl.sodium()
    }
}