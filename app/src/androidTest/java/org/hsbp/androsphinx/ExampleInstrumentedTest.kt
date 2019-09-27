package org.hsbp.androsphinx

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4

import org.junit.Test
import org.junit.runner.RunWith

import org.junit.Assert.*

/**
 * Instrumented test, which will execute on an Android device.
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */

@Suppress("SpellCheckingInspection")
const val EXPECTED_BASIC_TEST = "Dnw7PR+5GmrE/t6RtaF12gPIQSWaIGaSje7RgQvasy4="

@Suppress("SpellCheckingInspection")
const val RWD_INPUT = "vb4s5n4Vp1sJCouiXfwoTpBvfglolAUXq4oomcbPZIc="

@Suppress("SpellCheckingInspection")
const val DERIVED_UL_20 = "uCxTTIPTPQdFWvomUAaZ"

@Suppress("SpellCheckingInspection")
const val DERIVED_U_20 = "UFODYHKPMJABWGWQHYTM"

@Suppress("SpellCheckingInspection")
const val DERIVED_ULSD_20 = "jT1'GCa@7]]|2w!3E*B="

@RunWith(AndroidJUnit4::class)
class ExampleInstrumentedTest {
    @Test
    fun sphinxBasicTest() {
        val c = Sphinx.Challenge("shitty password\u0000".toCharArray())
        val secret = ByteArray(32) { ' '.toByte() }
        val resp = Sphinx.respond(c.challenge, secret)
        val rwd = c.finish(resp)
        assertArrayEquals(rwd, Base64.decode(EXPECTED_BASIC_TEST, Base64.DEFAULT))
    }

    @Test
    fun encodingTest() {
        val rwd = Base64.decode(RWD_INPUT, Base64.DEFAULT)

        val pwdUL20 = CharacterClass.derive(rwd,
            setOf(CharacterClass.UPPER, CharacterClass.LOWER), 20)
        assertArrayEquals(pwdUL20, DERIVED_UL_20.toCharArray())

        val pwdU20 = CharacterClass.derive(rwd,
            setOf(CharacterClass.UPPER), 20)
        assertArrayEquals(pwdU20, DERIVED_U_20.toCharArray())

        val pwdULSD20 = CharacterClass.derive(rwd,
            CharacterClass.values().toSet(), 20)
        assertArrayEquals(pwdULSD20, DERIVED_ULSD_20.toCharArray())
    }
}
