package org.hsbp.androsphinx

import android.content.ContentValues
import android.content.Context
import android.content.SharedPreferences
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import androidx.preference.PreferenceManager
import java.io.FileNotFoundException
import java.lang.Exception

const val FILE_NAME_KEY = "key"
const val FILE_NAME_SALT = "salt"

const val SHARED_PREFERENCES_KEY_HOST = "host"
const val SHARED_PREFERENCES_KEY_PORT = "port"
const val SHARED_PREFERENCES_KEY_SERVER_PK = "server_pk"
const val SHARED_PREFERENCES_KEY_USE_TLS = "use_tls"

const val DB_VERSION: Int = 1
const val USERS_TABLE: String = "users"
const val HOST_ID: String = "host_id"
const val USERNAME: String = "username"

// TODO encrypt before storage / decrypt after retrieval using Android Key Store

class AndroidCredentialStore(private val ctx: Context) : Protocol.CredentialStore {
    val isSetUpForCommunication: Boolean
        get() = host.isNotEmpty() and (port != 0) and try { serverPublicKey.asBytes.isNotEmpty() } catch(e: Exception) { false }

    override val key: Ed25519PrivateKey
        get() = loadFileOrGenerate(FILE_NAME_KEY, Ed25519PrivateKey.Companion::generate, Ed25519PrivateKey.Companion::fromByteArray)

    override val salt: Salt
        get() = loadFileOrGenerate(FILE_NAME_SALT, Salt.Companion::generate, Salt.Companion::fromByteArray)

    private fun <T : KeyMaterial> loadFileOrGenerate(name: String, generator: () -> T, reader: (ByteArray) -> T): T {
        try {
            ctx.openFileInput(name).use {
                return reader(it.readBytes())
            }
        } catch (e: FileNotFoundException) {
            val gen = generator()
            ctx.openFileOutput(name, Context.MODE_PRIVATE).use {
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

    override val serverPublicKey: Ed25519PublicKey
        get() = Ed25519PublicKey.fromBase64(sharedPreferences.getString(SHARED_PREFERENCES_KEY_SERVER_PK, "")!!)

    private val sharedPreferences: SharedPreferences
        get() = PreferenceManager.getDefaultSharedPreferences(ctx)

    override fun cacheUser(hostId: ByteArray, username: String) {
        UserCache(ctx).writableDatabase.use { db ->
            db.insertOrThrow(USERS_TABLE, null, ContentValues(1).apply {
                put(HOST_ID, hostId)
                put(USERNAME, username)
            })
        }
    }

    override fun getUsers(hostId: ByteArray): List<String> {
        UserCache(ctx).readableDatabase.use { db ->
            db.rawQuery("SELECT $USERNAME FROM $USERS_TABLE WHERE $HOST_ID = x'${hostId.asHex}'", null).use { c ->
                return generateSequence { if (c.moveToNext()) c.getString(0) else null }.toList()
            }
        }
    }

    override fun deleteUser(hostId: ByteArray, username: String) {
        UserCache(ctx).writableDatabase.use { db ->
            db.execSQL("DELETE FROM $USERS_TABLE WHERE $HOST_ID = x'${hostId.asHex}' AND $USERNAME = ?", arrayOf(username))
        }
    }
}

val ByteArray.asHex: String
    get() = this.joinToString(separator = "") { it.toInt().and(0xFF).toString(16).padStart(2, '0') }

class UserCache(context: Context) : SQLiteOpenHelper(context, "user_cache", null, DB_VERSION) {
    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL("""CREATE TABLE IF NOT EXISTS $USERS_TABLE ($HOST_ID BLOB NOT NULL,
            $USERNAME VARCHAR NOT NULL, PRIMARY KEY ($HOST_ID, $USERNAME));""")
        db.execSQL("CREATE INDEX IF NOT EXISTS host_index ON $USERS_TABLE ($HOST_ID);")
    }

    override fun onUpgrade(db: SQLiteDatabase?, old: Int, new: Int) { /* nothing yet */ }
}

fun Context.storeServerInfo(host: String, port: Int, serverPublicKey: Ed25519PublicKey) {
    with(PreferenceManager.getDefaultSharedPreferences(this).edit()) {
        putString(SHARED_PREFERENCES_KEY_HOST, host)
        putInt(SHARED_PREFERENCES_KEY_PORT, port)
        putString(SHARED_PREFERENCES_KEY_SERVER_PK, serverPublicKey.asBase64)
        commit()
    }
}