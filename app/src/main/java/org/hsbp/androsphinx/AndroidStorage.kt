// SPDX-FileCopyrightText: 2019, Andras Veres-Szentkiralyi <vsza@vsza.hu>
// SPDX-License-Identifier: MIT

package org.hsbp.androsphinx

import android.content.Context
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKeys
import java.io.File

private const val FILE_NAME_CONFIG = "config"
private val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)


class AndroidCredentialStore(private val ctx: Context) : Protocol.CredentialStore {

    fun updateSettings(source: Protocol.CredentialStore) {
        val plainBytes = ShareType.PRIVATE.serialize(source)
        encryptedKeyFile.openFileOutput().use {
            it.write(plainBytes)
        }
    }

    private val encryptedSerializedCredentialStore: SerializedCredentialStore // TODO cache this
        get() = encryptedKeyFile.openFileInput().use {
            SerializedCredentialStore(it.readBytes())
        }

    val isSetUpForCommunication: Boolean
        get() = configFileExists && servers.isNotEmpty()

    override val key: MasterKey
        get() = encryptedSerializedCredentialStore.key

    override val servers: List<Protocol.Server>
        get() = encryptedSerializedCredentialStore.servers

    val configFileExists: Boolean
        get() = configFile.exists()

    private val encryptedKeyFile: EncryptedFile
        get() = EncryptedFile.Builder(configFile, ctx, masterKeyAlias,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
        ).build()

    private val configFile: File
        get() = File(ctx.filesDir, FILE_NAME_CONFIG)

    override val rwdKeys: Boolean
        get() = encryptedSerializedCredentialStore.rwdKeys

    override val threshold: Int
        get() = encryptedSerializedCredentialStore.threshold
}
