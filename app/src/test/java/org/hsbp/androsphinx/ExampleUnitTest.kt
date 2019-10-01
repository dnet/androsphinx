package org.hsbp.androsphinx

import org.junit.Test

import org.junit.Assert.*
import java.util.*

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */

@Suppress("SpellCheckingInspection")
const val RWD_INPUT = "vb4s5n4Vp1sJCouiXfwoTpBvfglolAUXq4oomcbPZIc="

@Suppress("SpellCheckingInspection")
const val DERIVED_UL_20 = "uCxTTIPTPQdFWvomUAaZ"

@Suppress("SpellCheckingInspection")
const val DERIVED_U_20 = "UFODYHKPMJABWGWQHYTM"

@Suppress("SpellCheckingInspection")
const val DERIVED_ULSD_20 = "jT1'GCa@7]]|2w!3E*B="

class ExampleUnitTest {
    @Test
    fun encodingTest() {
        val rwd = Base64.getDecoder().decode(RWD_INPUT)

        val pwdUL20 = CharacterClass.derive(rwd,
            setOf(CharacterClass.UPPER, CharacterClass.LOWER), 20)
        assertArrayEquals(DERIVED_UL_20.toCharArray(), pwdUL20)

        val pwdU20 = CharacterClass.derive(rwd,
            setOf(CharacterClass.UPPER), 20)
        assertArrayEquals(DERIVED_U_20.toCharArray(), pwdU20)

        val pwdULSD20 = CharacterClass.derive(rwd,
            CharacterClass.values().toSet(), 20)
        assertArrayEquals(DERIVED_ULSD_20.toCharArray(), pwdULSD20)
    }

    @Test
    fun characterClassSerializationTest() {
        for (expected in 0 .. 15) {
            val set = CharacterClass.parse(expected.toByte())
            val serialized = CharacterClass.serialize(set)
            assertEquals(expected.toByte(), serialized)
        }
    }
}
