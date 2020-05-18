package org.hsbp.androsphinx

import android.content.Context
import android.content.SharedPreferences
import androidx.preference.PreferenceManager
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKeys
import java.io.FileNotFoundException
import java.io.File

private const val FILE_NAME_KEY = "key"
private val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)

const val SHARED_PREFERENCES_KEY_HOST = "host"
const val SHARED_PREFERENCES_KEY_PORT = "port"

class AndroidCredentialStore(private val ctx: Context) : Protocol.CredentialStore {
    val isSetUpForCommunication: Boolean
        get() = host.isNotEmpty() and (port != 0)

    override val key: MasterKey
        get() = try {
            keyFile.openFileInput().use {
                MasterKey.fromByteArray(it.readBytes())
            }
        } catch (e: FileNotFoundException) {
            MasterKey.generate().also(this::writeMasterKey)
        }

    fun writeMasterKey(newKey: MasterKey) {
        keyFile.openFileOutput().use {
            it.write(newKey.asBytes)
        }
    }

    private val keyFile: EncryptedFile
        get() = EncryptedFile.Builder(
            File(ctx.filesDir, FILE_NAME_KEY), ctx, masterKeyAlias,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
        ).build()

    override val host: String
        get() = sharedPreferences.getString(SHARED_PREFERENCES_KEY_HOST, "")!!

    override val port: Int
        get() = sharedPreferences.getInt(SHARED_PREFERENCES_KEY_PORT, 0)

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