package org.hsbp.androsphinx

import android.content.ContentValues
import android.content.Context
import android.content.SharedPreferences
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.util.Base64
import java.io.FileNotFoundException

const val SALT_BYTES = 32
const val SHARED_PREFERENCES_NAME = "androsphinx"
const val SHARED_PREFERENCES_KEY_HOST = "host"
const val SHARED_PREFERENCES_KEY_PORT = "port"
const val SHARED_PREFERENCES_KEY_SERVER_PK = "server_pk"

const val DB_VERSION: Int = 1
const val USERS_TABLE: String = "users"
const val HOST_ID: String = "host_id"
const val USERNAME: String = "username"

// TODO encrypt before storage / decrypt after retrieval using Android Key Store

class AndroidCredentialStore(private val ctx: Context) : Protocol.CredentialStore {
    override val key: ByteArray
        get() = loadFileOrGenerate("key", ::cryptoSignKeyPair)

    override val salt: ByteArray
        get() = loadFileOrGenerate("salt") { randomBytes(SALT_BYTES) }

    private fun loadFileOrGenerate(name: String, generator: () -> ByteArray): ByteArray {
        try {
            ctx.openFileInput(name).use {
                return it.readBytes()
            }
        } catch (e: FileNotFoundException) {
            val gen = generator()
            ctx.openFileOutput(name, Context.MODE_PRIVATE).use {
                it.write(gen)
            }
            return gen
        }
    }

    override val host: String
        get() = sharedPreferences.getString(SHARED_PREFERENCES_KEY_HOST, "")!!

    override val port: Int
        get() = sharedPreferences.getInt(SHARED_PREFERENCES_KEY_PORT, 0)

    override val serverPublicKey: ByteArray
        get() = Base64.decode(sharedPreferences.getString(SHARED_PREFERENCES_KEY_SERVER_PK, "")!!, Base64.DEFAULT)

    private val sharedPreferences: SharedPreferences
        get() = ctx.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)

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

fun Context.storeServerInfo(host: String, port: Int, serverPublicKey: ByteArray) {
    with(getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE).edit()) {
        putString(SHARED_PREFERENCES_KEY_HOST, host)
        putInt(SHARED_PREFERENCES_KEY_PORT, port)
        putString(SHARED_PREFERENCES_KEY_SERVER_PK,
            Base64.encodeToString(serverPublicKey, Base64.DEFAULT))
        commit()
    }
}