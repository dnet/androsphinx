package org.hsbp.androsphinx

import org.junit.Test

import org.junit.Assert.*
import java.math.BigInteger
import java.util.*

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */

@Suppress("SpellCheckingInspection")
const val RWD_INPUT = "vb4s5n4Vp1sJCouiXfwoTpBvfglolAUXq4oomcbPZIc="

@Suppress("SpellCheckingInspection")
const val DERIVED_UL_20 = "AZfYNTiUccgliDzrVQev"

@Suppress("SpellCheckingInspection")
const val DERIVED_U_20 = "IRVGNTDGXOKTTVUSOOJV"

@Suppress("SpellCheckingInspection")
const val DERIVED_ULSD_20 = "oSSF6EHjPau%po#rkwX4"
@Suppress("SpellCheckingInspection")
const val DERIVED_ULSD_20_SYMBOLS = ".:;#\$%&" // not sorted on purpose

@Suppress("SpellCheckingInspection")
const val TEST_XOR_MASK = "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210"

class ExampleUnitTest {
    @Test
    fun encodingTest() {
        val rwd = BigInteger(POSITIVE, Base64.getDecoder().decode(RWD_INPUT))

        val pwdUL20 = CharacterClass.derive(rwd,
            setOf(CharacterClass.UPPER, CharacterClass.LOWER), 20, emptySet())
        assertArrayEquals(DERIVED_UL_20.toCharArray(), pwdUL20)

        val pwdU20 = CharacterClass.derive(rwd,
            setOf(CharacterClass.UPPER), 20, emptySet())
        assertArrayEquals(DERIVED_U_20.toCharArray(), pwdU20)

        val pwdULSD20 = CharacterClass.derive(rwd,
            CharacterClass.values().toSet(), 20, DERIVED_ULSD_20_SYMBOLS.toSet())
        assertArrayEquals(DERIVED_ULSD_20.toCharArray(), pwdULSD20)
    }

    @Test
    fun characterClassSerializationTest() {
        for (expected in 0 .. 7) {
            val set = CharacterClass.parse(expected.toBigInteger())
            val serialized = CharacterClass.serialize(set)
            assertEquals(expected.toBigInteger(), serialized)
        }
    }

    @Test
    fun ruleSerializationTest() {
        val upperLower20 = Rule(setOf(CharacterClass.UPPER, CharacterClass.LOWER),
            emptySet(), 20.toBigInteger(), BigInteger.ZERO, BigInteger.ZERO)
        val upperLower20bytes = upperLower20.serialize()
        assertEquals(RULE_BYTES_LENGTH, upperLower20bytes.size)
        assertEquals(Rule.parse(upperLower20bytes), upperLower20)
        val upperLowerSelectSymbols20xor = Rule(setOf(CharacterClass.UPPER, CharacterClass.LOWER),
            DERIVED_ULSD_20_SYMBOLS.toSet(), 20.toBigInteger(), BigInteger(TEST_XOR_MASK, 16), 23.toBigInteger())
        val upperLowerSelectSymbols20xorBytes = upperLowerSelectSymbols20xor.serialize()
        assertEquals(RULE_BYTES_LENGTH, upperLowerSelectSymbols20xorBytes.size)
        assertEquals(Rule.parse(upperLowerSelectSymbols20xorBytes), upperLowerSelectSymbols20xor)
        val upperLowerSelectSymbols20xorS = Rule(setOf(CharacterClass.UPPER, CharacterClass.LOWER, CharacterClass.SYMBOLS),
            DERIVED_ULSD_20_SYMBOLS.toSet(), 20.toBigInteger(), BigInteger(TEST_XOR_MASK, 16), 23.toBigInteger())
        assertEquals(Rule.parse(upperLowerSelectSymbols20xorS.serialize()), upperLowerSelectSymbols20xor)
    }
}
