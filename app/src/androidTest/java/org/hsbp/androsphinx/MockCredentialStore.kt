package org.hsbp.androsphinx

import android.util.Base64
import com.danrusu.pods4k.immutableArrays.ImmutableByteArray
import com.danrusu.pods4k.immutableArrays.buildImmutableByteArray

/**
 * 
 * SPDX-FileCopyrightText: 2019, Andras Veres-Szentkiralyi <vsza@vsza.hu>
 * SPDX-License-Identifier: MIT
 */

@Suppress("SpellCheckingInspection")
const val MOCK_KEY = "TOYfTdPacDTemFBo1z6CtEfkkmvWJJ1/zdtTnB1arr4="

@Suppress("SpellCheckingInspection")
val LONG_TERM_KEYS = arrayOf(
    "laIZOz6No/2A603+dE1lhok98fkClMH00OdAA6rUVj4=",
    "y4ndsuWqxEMrFbvAnqvZyq54qXq0L2XdsgK86gB//Tk=",
    "voMViVAZ/Krg+vRl+kmm0cOhPEX76YSEu5xnuc+vbDM=",
    "8hXvLlK24mtaZG40cqaCIm0mqlgjAYHZboS3CAshpTM=",
    "CtzTT5jA6v/LwP6Ks1NMeuh3/EqfabUGs2YeuEAr84I=",
)

class MockCredentialStore : Protocol.CredentialStore {
    override val key: MasterKey
        get() = MasterKey.fromByteArray(Base64.decode(MOCK_KEY, Base64.DEFAULT))

    override val servers: List<Protocol.Server>
        get() = (1..5).map {
            Protocol.Server(name="oracle$it", host="oracle$it.sphinx.s2i.ninja", port=23550+it,
                longTermSignatureKey = ImmutableByteArray.copyFrom(
                    kotlin.io.encoding.Base64.decode(LONG_TERM_KEYS[it - 1]),
                    0, CRYPTO_SIGN_PUBLICKEYBYTES))
        }

    override val rwdKeys: Boolean
        get() = false

    override val threshold: Int
        get() = 3
}
