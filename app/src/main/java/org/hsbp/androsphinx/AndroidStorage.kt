package org.hsbp.androsphinx

import android.content.Context
import android.content.SharedPreferences
import androidx.preference.PreferenceManager
import java.io.FileNotFoundException

const val FILE_NAME_KEY = "key"

const val SHARED_PREFERENCES_KEY_HOST = "host"
const val SHARED_PREFERENCES_KEY_PORT = "port"
const val SHARED_PREFERENCES_KEY_USE_TLS = "use_tls"

// TODO encrypt before storage / decrypt after retrieval using Android Key Store

class AndroidCredentialStore(private val ctx: Context) : Protocol.CredentialStore {
    val isSetUpForCommunication: Boolean
        get() = host.isNotEmpty() and (port != 0)

    override val key: MasterKey
        get() {
            try {
                ctx.openFileInput(FILE_NAME_KEY).use {
                    return MasterKey.fromByteArray(it.readBytes())
                }
            } catch (e: FileNotFoundException) {
                val gen = MasterKey.generate()
                ctx.openFileOutput(FILE_NAME_KEY, Context.MODE_PRIVATE).use {
                    it.write(gen.asBytes)
                }
                return gen
            }
        }

    override val host: String
        get() = sharedPreferences.getString(SHARED_PREFERENCES_KEY_HOST, "")!!

    override val port: Int
        get() = sharedPreferences.getInt(SHARED_PREFERENCES_KEY_PORT, 0)

    override val useTls: Boolean
        get() = sharedPreferences.getBoolean(SHARED_PREFERENCES_KEY_USE_TLS, true)

    private val sharedPreferences: SharedPreferences
        get() = PreferenceManager.getDefaultSharedPreferences(ctx)
}

fun Context.storeServerInfo(host: String, port: Int) {
    with(PreferenceManager.getDefaultSharedPreferences(this).edit()) {
        putString(SHARED_PREFERENCES_KEY_HOST, host)
        putInt(SHARED_PREFERENCES_KEY_PORT, port)
        commit()
    }
}