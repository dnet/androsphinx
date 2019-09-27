package org.hsbp.androsphinx

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import java.io.File
import java.io.FileNotFoundException

const val SALT_BYTES = 32
const val BASE64_FLAGS = Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
const val SHARED_PREFERENCES_NAME = "androsphinx"
const val SHARED_PREFERENCES_KEY_HOST = "host"
const val SHARED_PREFERENCES_KEY_PORT = "port"

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

    private val sharedPreferences: SharedPreferences
        get() = ctx.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)

    override fun cacheUser(hostId: ByteArray, username: String) {
        val filename = Base64.encodeToString(hostId, BASE64_FLAGS)
        val f = File(ctx.cacheDir, filename)
        if (f.exists()) f.appendText("\n$username") else f.writeText(username)
    }

    override fun getUsers(hostId: ByteArray): List<String> {
        val filename = Base64.encodeToString(hostId, BASE64_FLAGS)
        return try {
            File(ctx.cacheDir, filename).readLines()
        } catch (e: FileNotFoundException) {
            emptyList()
        }
    }

    override fun deleteUser(hostId: ByteArray, username: String) {
        val filename = Base64.encodeToString(hostId, BASE64_FLAGS)
        try {
            val oldFile = File(ctx.cacheDir, filename)
            val users = oldFile.useLines { oldUserList ->
                oldUserList.filter { it != username }.joinToString(separator = "\n").toByteArray()
            }
            if (users.size.toLong() == oldFile.length()) return

            val newFile = File(ctx.cacheDir, "$filename.tmp")
            newFile.outputStream().use {
                it.write(users)
            }
            newFile.renameTo(oldFile)

        } catch (e: FileNotFoundException) {
            // nothing to delete
        }
    }
}

